package backend

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/dnsdata"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
	"github.com/lauritsk/sambatui/internal/lifecycle"
	"github.com/miekg/dns"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/record"
)

type Action struct {
	Kind, Zone, Name, Type, Value, OldValue, DN, Revision, EntryKind, Parent string
	Attributes                                                               map[string]string
	Flags                                                                    uint32
}
type Plan struct {
	Title   string
	Actions []Action
}

func (p Plan) Clone() Plan {
	out := Plan{Title: p.Title, Actions: append([]Action(nil), p.Actions...)}
	for i, a := range out.Actions {
		if a.Attributes != nil {
			attrs := map[string]string{}
			for k, v := range a.Attributes {
				attrs[k] = v
			}
			out.Actions[i].Attributes = attrs
		}
	}
	return out
}

func (p Plan) Validate(s config.Settings) error {
	if len(p.Actions) == 0 {
		return errors.New("empty write plan")
	}
	for _, a := range p.Actions {
		switch a.Kind {
		case "dns_add", "dns_delete", "dns_update":
			if !dnsdata.ValidName(a.Zone, false) {
				return errors.New("invalid DNS zone")
			}
			if _, e := dnsdata.Parse(a.Name, a.Type, a.Value); e != nil {
				return e
			}
			if a.Kind == "dns_update" {
				if _, e := dnsdata.Parse(a.Name, a.Type, a.OldValue); e != nil {
					return e
				}
			}
		case "ldap_add":
			if !directory.InScope(a.Parent, s.BaseDN) {
				return errors.New("LDAP add outside configured base")
			}
			if _, e := directory.BuildAdd(a.EntryKind, a.Parent, a.Name, a.Attributes); e != nil {
				return e
			}
		case "ldap_modify", "ldap_delete", "ldap_disable":
			if !directory.InScope(a.DN, s.BaseDN) {
				return errors.New("LDAP target outside configured base")
			}
			if _, e := directory.Assertion(a.Revision, nil); e != nil {
				return e
			}
			if a.Kind == "ldap_delete" && directory.EqualDN(a.DN, s.BaseDN) {
				return errors.New("refusing to delete LDAP base")
			}
			if a.Kind == "ldap_modify" {
				for attr := range a.Attributes {
					ok := false
					for _, allowed := range directory.Editable[a.EntryKind] {
						if attr == allowed {
							ok = true
						}
					}
					if !ok {
						return errors.New("LDAP attribute not editable")
					}
				}
			}
		default:
			return errors.New("invalid write action")
		}
	}
	return nil
}

func (p Plan) Preview() string {
	text := p.Title + "\n"
	for _, a := range p.Actions {
		a.Zone = fmt.Sprintf("%q", a.Zone)
		a.Name = fmt.Sprintf("%q", a.Name)
		a.Value = fmt.Sprintf("%q", a.Value)
		a.OldValue = fmt.Sprintf("%q", a.OldValue)
		a.DN = fmt.Sprintf("%q", a.DN)
		a.Parent = fmt.Sprintf("%q", a.Parent)
		switch a.Kind {
		case "dns_add":
			text += fmt.Sprintf("Add %s: %s %s %s (TTL 900s)\n", a.Zone, a.Name, a.Type, a.Value)
		case "dns_update":
			text += fmt.Sprintf("Update %s: %s %s\nOld: %s\nNew: %s\n", a.Zone, a.Name, a.Type, a.OldValue, a.Value)
		case "dns_delete":
			text += fmt.Sprintf("Delete %s: %s %s %s\n", a.Zone, a.Name, a.Type, a.Value)
		case "ldap_add":
			text += fmt.Sprintf("Add %s %s below %s\n", a.EntryKind, a.Name, a.Parent)
		case "ldap_modify":
			text += fmt.Sprintf("Modify %s at revision %s\n", a.DN, a.Revision)
			keys := []string{}
			for k := range a.Attributes {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				text += fmt.Sprintf("%q = %q\n", k, a.Attributes[k])
			}
		case "ldap_delete":
			text += fmt.Sprintf("DELETE %s at revision %s\n", a.DN, a.Revision)
		case "ldap_disable":
			text += fmt.Sprintf("Disable %s at revision %s; UAC %d -> %d\n", a.DN, a.Revision, a.Flags, a.Flags|2)
		}
	}
	return text + "No rollback. No automatic retry. Partial/unknown outcomes require inspection."
}

type Service interface {
	CheckLDAP(context.Context, config.Settings) error
	Zones(context.Context, config.Settings) ([]string, error)
	Records(context.Context, config.Settings, string, string, uint16) ([]dnsrpc.Row, error)
	Search(context.Context, config.Settings, string, string, string, int) ([]directory.Entry, error)
	Execute(context.Context, config.Settings, Plan) lifecycle.Outcome
}
type Native struct{}

func (Native) CheckLDAP(ctx context.Context, s config.Settings) error {
	return directory.New(s.LDAP()).Check(ctx)
}

func (Native) Zones(ctx context.Context, s config.Settings) ([]string, error) {
	c, e := dnsrpc.Dial(ctx, s.DNS())
	if e != nil {
		return nil, e
	}
	defer c.Close()
	return c.Zones(ctx)
}

func (Native) Records(ctx context.Context, s config.Settings, zone, node string, typ uint16) ([]dnsrpc.Row, error) {
	c, e := dnsrpc.Dial(ctx, s.DNS())
	if e != nil {
		return nil, e
	}
	defer c.Close()
	return c.Records(ctx, zone, node, typ)
}

func (Native) Search(ctx context.Context, s config.Settings, base, kind, text string, limit int) ([]directory.Entry, error) {
	return directory.New(s.LDAP()).Search(ctx, base, kind, text, limit)
}

func (Native) Execute(ctx context.Context, s config.Settings, p Plan) lifecycle.Outcome {
	if e := ctx.Err(); e != nil {
		return lifecycle.Outcome{Err: e}
	}
	p = p.Clone()
	if e := p.Validate(s); e != nil {
		return lifecycle.Outcome{Err: e}
	}
	for i, a := range p.Actions {
		if e := ctx.Err(); e != nil {
			return lifecycle.Outcome{Err: e, Uncertain: i > 0}
		}
		var e error
		uncertain := false
		switch a.Kind {
		case "dns_add", "dns_update", "dns_delete":
			encode := func(value string) (*record.Record, error) {
				rr, e := dnsdata.Parse(a.Name, a.Type, value)
				if e != nil {
					return nil, e
				}
				return dnsrpc.Encode(rr)
			}
			var old, new *record.Record
			if a.Kind == "dns_add" {
				new, e = encode(a.Value)
			} else if a.Kind == "dns_delete" {
				old, e = encode(a.Value)
			} else {
				old, e = encode(a.OldValue)
				if e == nil {
					new, e = encode(a.Value)
				}
			}
			if e == nil {
				var c *dnsrpc.Client
				c, e = dnsrpc.Dial(ctx, s.DNS())
				if e == nil {
					if a.Kind == "dns_update" {
						e = c.Replace(ctx, a.Zone, a.Name, old, new)
					} else {
						e = c.Mutate(ctx, a.Zone, a.Name, old, new)
					}
					c.Close()
					var unknown *dnsrpc.UncertainError
					uncertain = errors.As(e, &unknown)
				}
			}
		case "ldap_add":
			_, e = directory.New(s.LDAP()).Add(ctx, a.EntryKind, a.Parent, a.Name, a.Attributes)
		case "ldap_modify":
			e = directory.New(s.LDAP()).Modify(ctx, a.DN, a.EntryKind, a.Revision, a.Attributes)
		case "ldap_delete":
			e = directory.New(s.LDAP()).Delete(ctx, a.DN, a.Revision)
		case "ldap_disable":
			e = directory.New(s.LDAP()).Disable(ctx, a.DN, a.Revision, a.Flags)
		default:
			e = errors.New("invalid write action")
		}
		var u *directory.UncertainError
		uncertain = uncertain || errors.As(e, &u)
		if e != nil {
			return lifecycle.Outcome{Err: fmt.Errorf("%d of %d operations acknowledged before failure: %w", i, len(p.Actions), e), Uncertain: uncertain}
		}
	}
	return lifecycle.Outcome{}
}

// Inspect never writes, and never clears the write guard itself. A missing
// target is reported as absence, not interpreted as cancellation or rollback.
func Inspect(ctx context.Context, service Service, s config.Settings, p Plan) (string, error) {
	report := p.Preview() + "\nObserved state on original DC:\n"
	for _, a := range p.Actions {
		if a.Zone != "" {
			rows, e := service.Records(ctx, s, a.Zone, a.Name, dns.TypeANY)
			if e != nil {
				var st *dnsrpc.StatusError
				if !errors.As(e, &st) || st.Code != 9714 {
					return "", e
				}
			}
			report += fmt.Sprintf("%s:%s — %d returned records\n", a.Zone, a.Name, len(rows))
			for _, r := range rows {
				report += fmt.Sprintf("%s %s %s\n", r.Name, r.Type, r.Value)
			}
		} else {
			dn := a.DN
			if a.Kind == "ldap_add" {
				req, e := directory.BuildAdd(a.EntryKind, a.Parent, a.Name, a.Attributes)
				if e != nil {
					return "", e
				}
				dn = req.DN
			}
			rows, e := service.Search(ctx, s, dn, "all", "", 0)
			if e != nil && !ldap.IsErrorWithCode(e, ldap.LDAPResultNoSuchObject) {
				return "", e
			}
			report += fmt.Sprintf("%s — %d returned entries\n", dn, len(rows))
			for _, r := range rows {
				report += fmt.Sprintf("revision=%s UAC=%s description=%s mail=%s\n", r.Revision, r.First("userAccountControl"), r.First("description"), r.First("mail"))
			}
		}
	}
	return report, nil
}

func ParseQueryType(s string) (uint16, error) {
	s = strings.ToUpper(s)
	if s == "" || s == "ALL" {
		return dns.TypeANY, nil
	}
	if t, ok := dns.StringToType[s]; ok {
		return t, nil
	}
	return 0, errors.New("invalid DNS query type")
}
