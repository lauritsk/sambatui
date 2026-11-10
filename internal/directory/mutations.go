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

func decimal(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func Assertion(revision string, flags *uint32) (ldap.Control, error) {
	if !decimal(revision) {
		return nil, errors.New("missing or invalid LDAP revision; refresh before writing")
	}
	f := "(&(uSNChanged=" + revision + ")"
	if flags != nil {
		f += "(userAccountControl=" + strconv.FormatUint(uint64(*flags), 10) + ")"
	}
	f += ")"
	packet, e := ldap.CompileFilter(f)
	if e != nil {
		return nil, e
	}
	return ldap.NewControlString(AssertionOID, true, string(packet.Bytes())), nil
}

func InScope(dn, base string) bool {
	d, e := ldap.ParseDN(dn)
	if e != nil {
		return false
	}
	b, e := ldap.ParseDN(base)
	if e != nil || len(b.RDNs) == 0 {
		return false
	}
	return b.EqualFold(d) || b.AncestorOfFold(d)
}

func EqualDN(a, b string) bool {
	x, e := ldap.ParseDN(a)
	if e != nil {
		return false
	}
	y, e := ldap.ParseDN(b)
	return e == nil && x.EqualFold(y)
}

func (c *Client) scope(dn string) error {
	if !InScope(dn, c.cfg.BaseDN) {
		return errors.New("LDAP target must be at or below configured base DN")
	}
	return nil
}

type UncertainError struct{ Cause error }

func (e *UncertainError) Error() string {
	return "LDAP write outcome uncertain; cancellation/connection loss is not rollback. Read server state before retrying: " + e.Cause.Error()
}
func (e *UncertainError) Unwrap() error { return e.Cause }
func mutationError(e error) error {
	if e == nil {
		return nil
	}
	if ldap.IsErrorWithCode(e, ldap.LDAPResultAssertionFailed) {
		return errors.New("LDAP entry changed; refresh before retrying")
	}
	if ldap.IsErrorWithCode(e, ldap.LDAPResultUnavailableCriticalExtension) {
		return errors.New("server does not support critical conditional LDAP writes; refused without unsafe fallback")
	}
	var result *ldap.Error
	if errors.As(e, &result) && result.ResultCode > 0 && result.ResultCode < 200 {
		return fmt.Errorf("LDAP write refused: %w", e)
	}
	return &UncertainError{e}
}

func (c *Client) write(ctx context.Context, conditional bool, f func(Session) error) error {
	return c.with(ctx, func(s Session) error {
		if conditional {
			// Samba versions can omit the assertion capability. Do not send a write
			// merely hoping that an unadvertised critical control will be enforced.
			r, e := s.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{"supportedControl"}, nil))
			if e != nil {
				return fmt.Errorf("check conditional LDAP write support: %w", e)
			}
			supported := false
			for _, entry := range r.Entries {
				for _, oid := range entry.GetAttributeValues("supportedControl") {
					if oid == AssertionOID {
						supported = true
					}
				}
			}
			if !supported {
				return errors.New("server does not advertise critical conditional LDAP writes; refused without unsafe fallback")
			}
		}
		return mutationError(f(s))
	})
}

var Editable = map[string][]string{"user": {"displayName", "mail", "description"}, "group": {"description", "mail"}, "computer": {"description"}, "ou": {"description"}}

// ValidateChanges is shared by plan validation and dispatch so confirmation
// cannot approve attributes that the protocol boundary would refuse.
func ValidateChanges(kind string, changes map[string]string) error {
	for attribute := range changes {
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

func (c *Client) Modify(ctx context.Context, dn, kind, revision string, changes map[string]string) error {
	if e := c.scope(dn); e != nil {
		return e
	}
	control, e := Assertion(revision, nil)
	if e != nil {
		return e
	}
	if err := ValidateChanges(kind, changes); err != nil {
		return err
	}
	if len(changes) == 0 {
		return nil
	}
	req := ldap.NewModifyRequest(dn, []ldap.Control{control})
	keys := []string{}
	for k := range changes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, a := range keys {
		if changes[a] == "" {
			req.Delete(a, nil)
		} else {
			req.Replace(a, []string{changes[a]})
		}
	}
	return c.write(ctx, true, func(s Session) error { return s.Modify(req) })
}

func (c *Client) Delete(ctx context.Context, dn, revision string) error {
	if e := c.scope(dn); e != nil {
		return e
	}
	if EqualDN(dn, c.cfg.BaseDN) {
		return errors.New("refusing to delete LDAP base DN")
	}
	control, e := Assertion(revision, nil)
	if e != nil {
		return e
	}
	req := ldap.NewDelRequest(dn, []ldap.Control{control})
	return c.write(ctx, true, func(s Session) error { return s.Del(req) })
}

func (c *Client) Disable(ctx context.Context, dn, revision string, flags uint32) error {
	if e := c.scope(dn); e != nil {
		return e
	}
	control, e := Assertion(revision, &flags)
	if e != nil {
		return e
	}
	req := ldap.NewModifyRequest(dn, []ldap.Control{control})
	req.Replace("userAccountControl", []string{strconv.FormatUint(uint64(flags|2), 10)})
	return c.write(ctx, true, func(s Session) error { return s.Modify(req) })
}

func BuildAdd(kind, parent, name string, attrs map[string]string) (*ldap.AddRequest, error) {
	classes := map[string][]string{"user": {"top", "person", "organizationalPerson", "user"}, "group": {"top", "group"}, "computer": {"top", "person", "organizationalPerson", "user", "computer"}, "ou": {"top", "organizationalUnit"}}
	cl, ok := classes[kind]
	if !ok {
		return nil, errors.New("LDAP add kind must be user, group, computer or ou")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("LDAP add requires a name")
	}
	if _, e := ldap.ParseDN(parent); e != nil {
		return nil, e
	}
	rdn := "CN"
	if kind == "ou" {
		rdn = "OU"
	}
	req := ldap.NewAddRequest(rdn+"="+ldap.EscapeDN(name)+","+parent, nil)
	req.Attribute("objectClass", cl)
	values := map[string]string{}
	for k, v := range attrs {
		if v != "" {
			values[k] = v
		}
	}
	if kind == "ou" {
		values["ou"] = name
	} else {
		values["cn"] = name
	}
	if kind == "user" || kind == "group" {
		if values["sAMAccountName"] == "" {
			values["sAMAccountName"] = name
		}
	}
	if kind == "group" && values["groupType"] == "" {
		values["groupType"] = "-2147483646"
	}
	if kind == "computer" {
		account := values["sAMAccountName"]
		if account == "" {
			account = name
		}
		values["sAMAccountName"] = strings.TrimRight(account, "$") + "$"
		if values["userAccountControl"] == "" {
			values["userAccountControl"] = "4128"
		}
	}
	keys := []string{}
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, a := range keys {
		req.Attribute(a, []string{values[a]})
	}
	return req, nil
}

func (c *Client) Add(ctx context.Context, kind, parent, name string, attrs map[string]string) (string, error) {
	if e := c.scope(parent); e != nil {
		return "", e
	}
	req, e := BuildAdd(kind, parent, name, attrs)
	if e != nil {
		return "", e
	}
	e = c.write(ctx, false, func(s Session) error { return s.Add(req) })
	return req.DN, e
}
