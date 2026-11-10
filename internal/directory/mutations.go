package directory

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

const AssertionOID = "1.3.6.1.1.12"

func decimal(text string) bool {
	if text == "" {
		return false
	}
	for _, character := range text {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func Assertion(revision string, flags *uint32) (ldap.Control, error) {
	if len(revision) > 20 || !decimal(revision) {
		return nil, errors.New("missing or invalid LDAP revision; refresh before writing")
	}
	filter := "(&(uSNChanged=" + revision + ")"
	if flags != nil {
		filter += "(userAccountControl=" + strconv.FormatUint(uint64(*flags), 10) + ")"
	}
	filter += ")"
	packet, err := ldap.CompileFilter(filter)
	if err != nil {
		return nil, err
	}
	return ldap.NewControlString(AssertionOID, true, string(packet.Bytes())), nil
}

func InScope(dn, base string) bool {
	if len(dn) > dnBytesMax || len(base) > dnBytesMax {
		return false
	}
	targetDN, err := ldap.ParseDN(dn)
	if err != nil {
		return false
	}
	baseDN, err := ldap.ParseDN(base)
	if err != nil || len(baseDN.RDNs) == 0 {
		return false
	}
	return baseDN.EqualFold(targetDN) || baseDN.AncestorOfFold(targetDN)
}

func EqualDN(left, right string) bool {
	if len(left) > dnBytesMax || len(right) > dnBytesMax {
		return false
	}
	leftDN, err := ldap.ParseDN(left)
	if err != nil {
		return false
	}
	rightDN, err := ldap.ParseDN(right)
	return err == nil && leftDN.EqualFold(rightDN)
}

func (client *Client) scope(dn string) error {
	if !InScope(dn, client.settings.BaseDN) {
		return errors.New("LDAP target must be at or below configured base DN")
	}
	return nil
}

type UncertainError struct{ Cause error }

func (failure *UncertainError) Error() string {
	return "LDAP write outcome uncertain; cancellation/connection loss " +
		"is not rollback. Read server state before retrying: " +
		failure.Cause.Error()
}

func (failure *UncertainError) Unwrap() error {
	return failure.Cause
}

func mutationError(err error) error {
	if err == nil {
		return nil
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultAssertionFailed) {
		return errors.New("LDAP entry changed; refresh before retrying")
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailableCriticalExtension) {
		return errors.New(
			"server does not support critical conditional LDAP writes; " +
				"refused without unsafe fallback",
		)
	}
	var result *ldap.Error
	if errors.As(err, &result) && result.ResultCode > 0 && result.ResultCode < 200 {
		return fmt.Errorf("LDAP write refused: %w", err)
	}
	return &UncertainError{err}
}

func (client *Client) write(
	operationContext context.Context,
	conditional bool,
	operation func(Session) error,
) error {
	return client.with(operationContext, func(currentSession Session) error {
		if conditional {
			// Samba versions can omit the assertion capability. Do not send a write
			// merely hoping that an unadvertised critical control will be enforced.
			capabilities, currentErr := currentSession.Search(
				ldap.NewSearchRequest(
					"",
					ldap.ScopeBaseObject,
					ldap.NeverDerefAliases,
					1,
					0,
					false,
					"(objectClass=*)",
					[]string{"supportedControl"},
					nil,
				),
			)
			if currentErr != nil {
				return fmt.Errorf("check conditional LDAP write support: %w", currentErr)
			}
			if capabilities == nil || len(capabilities.Entries) != 1 ||
				len(capabilities.Referrals) > 0 {
				return errors.New(
					"invalid LDAP conditional-write capability result; refused " +
						"without unsafe fallback",
				)
			}
			if err := newReadBudget().entry(capabilities.Entries[0]); err != nil {
				return err
			}
			supported := false
			for _, entry := range capabilities.Entries {
				for _, oid := range entry.GetAttributeValues("supportedControl") {
					if oid == AssertionOID {
						supported = true
					}
				}
			}
			if !supported {
				return errors.New(
					"server does not advertise critical conditional LDAP writes; " +
						"refused without unsafe fallback",
				)
			}
		}
		return mutationError(operation(currentSession))
	})
}

var Editable = map[string][]string{
	"user":     {"displayName", "mail", "description"},
	"group":    {"description", "mail"},
	"computer": {"description"},
	"ou":       {"description"},
}

// ValidateChanges is shared by plan validation and dispatch so confirmation
// cannot approve attributes that the protocol boundary would refuse.
func ValidateChanges(kind string, changes map[string]string) error {
	if len(Editable[kind]) == 0 {
		return errors.New("LDAP entry kind is not editable")
	}
	if len(changes) > len(Editable[kind]) {
		return errors.New("too many LDAP attribute changes")
	}
	for attribute, value := range changes {
		if len(value) > filterBytesMax {
			return errors.New("LDAP attribute value exceeds safety limit")
		}
		allowed := false
		for _, editable := range Editable[kind] {
			if attribute == editable {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("LDAP attribute is not editable: %s", attribute)
		}
	}
	return nil
}

func (client *Client) Modify(
	operationContext context.Context,
	dn, kind, revision string,
	changes map[string]string,
) error {
	if currentErr := client.scope(dn); currentErr != nil {
		return currentErr
	}
	control, currentErr := Assertion(revision, nil)
	if currentErr != nil {
		return currentErr
	}
	if err := ValidateChanges(kind, changes); err != nil {
		return err
	}
	if len(changes) == 0 {
		return nil
	}
	request := ldap.NewModifyRequest(dn, []ldap.Control{control})
	keys := []string{}
	for key := range changes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, attribute := range keys {
		if changes[attribute] == "" {
			request.Delete(attribute, nil)
		} else {
			request.Replace(attribute, []string{changes[attribute]})
		}
	}
	return client.write(operationContext, true, func(session Session) error {
		return session.Modify(request)
	})
}

func (client *Client) Delete(operationContext context.Context, dn, revision string) error {
	if err := client.scope(dn); err != nil {
		return err
	}
	if EqualDN(dn, client.settings.BaseDN) {
		return errors.New("refusing to delete LDAP base DN")
	}
	control, err := Assertion(revision, nil)
	if err != nil {
		return err
	}
	request := ldap.NewDelRequest(dn, []ldap.Control{control})
	return client.write(operationContext, true, func(session Session) error {
		return session.Del(request)
	})
}

func (client *Client) Disable(
	operationContext context.Context,
	dn, revision string,
	flags uint32,
) error {
	if err := client.scope(dn); err != nil {
		return err
	}
	control, err := Assertion(revision, &flags)
	if err != nil {
		return err
	}
	request := ldap.NewModifyRequest(dn, []ldap.Control{control})
	request.Replace("userAccountControl", []string{strconv.FormatUint(uint64(flags|2), 10)})
	return client.write(operationContext, true, func(session Session) error {
		return session.Modify(request)
	})
}

func BuildAdd(kind, parent, name string, attributes map[string]string) (*ldap.AddRequest, error) {
	if err := validateAddSize(parent, name, attributes); err != nil {
		return nil, err
	}
	classes := map[string][]string{
		"user":     {"top", "person", "organizationalPerson", "user"},
		"group":    {"top", "group"},
		"computer": {"top", "person", "organizationalPerson", "user", "computer"},
		"ou":       {"top", "organizationalUnit"},
	}
	objectClasses, ok := classes[kind]
	if !ok {
		return nil, errors.New("LDAP add kind must be user, group, computer or ou")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("LDAP add requires a name")
	}
	if _, currentErr := ldap.ParseDN(parent); currentErr != nil {
		return nil, currentErr
	}
	rdn := "CN"
	if kind == "ou" {
		rdn = "OU"
	}
	request := ldap.NewAddRequest(rdn+"="+ldap.EscapeDN(name)+","+parent, nil)
	request.Attribute("objectClass", objectClasses)
	values := buildAddValues(kind, name, attributes)
	keys := []string{}
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, left := range keys {
		request.Attribute(left, []string{values[left]})
	}
	return request, nil
}

func (client *Client) Add(
	operationContext context.Context,
	kind, parent, name string,
	attributes map[string]string,
) (string, error) {
	if err := client.scope(parent); err != nil {
		return "", err
	}
	request, err := BuildAdd(kind, parent, name, attributes)
	if err != nil {
		return "", err
	}
	err = client.write(operationContext, false, func(session Session) error {
		return session.Add(request)
	})
	return request.DN, err
}
