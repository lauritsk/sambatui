package directory

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

const (
	rangePagesMax = 10000
	rangeBytesMax = 16 << 20
)

// Drain AD's ranged attributes on the same session: treating a ranged memberOf
// as absent would produce false hygiene findings. Publish only complete entries.
func expandRanges(ctx context.Context, session Session, entry *ldap.Entry) error {
	attributes := make([]*ldap.EntryAttribute, 0, len(entry.Attributes))
	seen := map[string]bool{}
	for _, attribute := range entry.Attributes {
		if attribute == nil {
			return errors.New("missing LDAP attribute")
		}
		base, spec, ranged := strings.Cut(strings.ToLower(attribute.Name), ";range=")
		if base == "" || seen[base] {
			return errors.New("ambiguous LDAP ranged attribute")
		}
		seen[base] = true
		if !ranged {
			attributes = append(attributes, attribute)
			continue
		}
		values, err := expandRange(ctx, session, entry.DN, attribute, spec)
		if err != nil {
			return err
		}
		attributes = append(attributes, ldap.NewEntryAttribute(base, values))
	}
	entry.Attributes = attributes
	return nil
}

func expandRange(
	ctx context.Context, session Session, dn string, attribute *ldap.EntryAttribute, spec string,
) ([]string, error) {
	base, _, _ := strings.Cut(strings.ToLower(attribute.Name), ";range=")
	var values []string
	expected, sizeBytes := 0, 0
	for page := 0; page < rangePagesMax; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		nextOffset, complete, err := rangeBounds(spec, expected, len(attribute.Values))
		if err != nil {
			return nil, err
		}
		// Check before copying: an oversized continuation must not double memory.
		for _, value := range attribute.Values {
			if len(value) > rangeBytesMax-sizeBytes {
				return nil, errors.New("LDAP ranged attribute exceeds read safety limit")
			}
			sizeBytes += len(value)
		}
		if len(attribute.Values) > rangeBytesMax-len(values) {
			return nil, errors.New("LDAP ranged attribute has too many values")
		}
		values = append(values, attribute.Values...)
		if complete {
			return values, nil
		}
		expected = nextOffset
		attribute, spec, err = rangeContinuation(session, dn, base, expected)
		if err != nil {
			return nil, err
		}
	}
	return nil, errors.New("LDAP ranged attribute exceeds page safety limit; no partial entry returned")
}

func rangeBounds(spec string, expected, count int) (int, bool, error) {
	first, last, ok := strings.Cut(spec, "-")
	start, err := strconv.Atoi(first)
	if !ok || err != nil || start != expected {
		return 0, false, errors.New("LDAP ranged attribute starts at an unexpected offset; refresh")
	}
	if last == "*" {
		return 0, true, nil
	}
	end, err := strconv.Atoi(last)
	// The successor is an offset too; require room for end+1 before adding.
	if err != nil || end < start || end == int(^uint(0)>>1) {
		return 0, false, errors.New("invalid LDAP ranged attribute bounds")
	}
	if end-start+1 != count {
		return 0, false, errors.New("LDAP ranged attribute length does not match bounds")
	}
	return end + 1, false, nil
}

func rangeContinuation(
	session Session, dn, base string, expected int,
) (*ldap.EntryAttribute, string, error) {
	request := ldap.NewSearchRequest(
		dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)",
		[]string{fmt.Sprintf("%s;range=%d-*", base, expected)},
		[]ldap.Control{ldap.NewControlString(ldap.ControlTypeMicrosoftDomainScope, true, "")},
	)
	result, err := session.Search(request)
	if err != nil {
		return nil, "", fmt.Errorf("LDAP ranged attribute read: %w", err)
	}
	if result == nil || len(result.Entries) != 1 || len(result.Referrals) > 0 {
		return nil, "", errors.New("LDAP ranged entry changed or was redirected; refresh")
	}
	entry := result.Entries[0]
	if entry == nil || !EqualDN(entry.DN, dn) {
		return nil, "", errors.New("LDAP ranged entry changed or was redirected; refresh")
	}
	var next *ldap.EntryAttribute
	var spec string
	for _, candidate := range entry.Attributes {
		if candidate == nil {
			return nil, "", errors.New("missing LDAP range continuation attribute")
		}
		name := strings.ToLower(candidate.Name)
		if strings.HasPrefix(name, base+";range=") {
			if next != nil {
				return nil, "", errors.New("ambiguous LDAP range continuation")
			}
			next = candidate
			spec = strings.TrimPrefix(name, base+";range=")
		}
	}
	if next == nil {
		return nil, "", errors.New("LDAP range continuation missing; refresh rather than accepting a partial entry")
	}
	return next, spec, nil
}
