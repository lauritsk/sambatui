package directory

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Drain AD's ranged attributes on the same session: treating a ranged memberOf
// as absent would produce false hygiene findings.
func expandRanges(ctx context.Context, s Session, entry *ldap.Entry) error {
	attributes := make([]*ldap.EntryAttribute, 0, len(entry.Attributes))
	seen := map[string]bool{}
	for _, a := range entry.Attributes {
		base, spec, ranged := strings.Cut(strings.ToLower(a.Name), ";range=")
		if !ranged {
			attributes = append(attributes, a)
			continue
		}
		if base == "" || seen[base] {
			return errors.New("ambiguous LDAP ranged attribute")
		}
		seen[base] = true
		values := append([]string(nil), a.Values...)
		size := 0
		for _, v := range values {
			size += len(v)
		}
		expected := 0
		for pages := 0; ; pages++ {
			if e := ctx.Err(); e != nil {
				return e
			}
			if pages > 10000 || size > 16<<20 {
				return errors.New("LDAP ranged attribute exceeds read safety limit; no partial entry returned")
			}
			first, last, ok := strings.Cut(spec, "-")
			start, e := strconv.Atoi(first)
			if !ok || e != nil || start != expected {
				return errors.New("LDAP ranged attribute starts at an unexpected offset; refresh")
			}
			if last == "*" {
				break
			}
			end, e := strconv.Atoi(last)
			if e != nil || end < start || end == int(^uint(0)>>1) {
				return errors.New("invalid LDAP ranged attribute bounds")
			}
			if end-start+1 != len(a.Values) {
				return errors.New("LDAP ranged attribute length does not match bounds")
			}
			expected = end + 1
			req := ldap.NewSearchRequest(entry.DN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{fmt.Sprintf("%s;range=%d-*", base, expected)}, []ldap.Control{ldap.NewControlString(ldap.ControlTypeMicrosoftDomainScope, true, "")})
			result, e := s.Search(req)
			if e != nil {
				return fmt.Errorf("LDAP ranged attribute read: %w", e)
			}
			if len(result.Entries) != 1 || len(result.Referrals) > 0 || !EqualDN(result.Entries[0].DN, entry.DN) {
				return errors.New("LDAP ranged entry changed or was redirected; refresh")
			}
			var next *ldap.EntryAttribute
			for _, candidate := range result.Entries[0].Attributes {
				name := strings.ToLower(candidate.Name)
				if strings.HasPrefix(name, base+";range=") {
					if next != nil {
						return errors.New("ambiguous LDAP range continuation")
					}
					next = candidate
					spec = strings.TrimPrefix(name, base+";range=")
				}
			}
			if next == nil {
				return errors.New("LDAP range continuation missing; refresh rather than accepting a partial entry")
			}
			a = next
			values = append(values, a.Values...)
			for _, v := range a.Values {
				size += len(v)
			}
		}
		attributes = append(attributes, ldap.NewEntryAttribute(base, values))
	}
	entry.Attributes = attributes
	return nil
}
