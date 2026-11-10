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

// MaxActions bounds confirmation size and sequential remote work per write flow.
const MaxActions = 5000

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

func (p Plan) Validate(settings config.Settings) error {
	if len(p.Actions) == 0 {
		return errors.New("empty write plan")
	}
	if len(p.Actions) > MaxActions {
		return fmt.Errorf("write plan exceeds %d actions", MaxActions)
	}
	for _, action := range p.Actions {
		if err := action.validate(settings); err != nil {
			return err
		}
	}
	return nil
}

func (a Action) validate(settings config.Settings) error {
	switch a.Kind {
	case "dns_add", "dns_delete", "dns_update":
		if !dnsdata.ValidName(a.Zone, false) {
			return errors.New("invalid DNS zone")
		}
		if _, err := dnsdata.Parse(a.Name, a.Type, a.Value); err != nil {
			return err
		}
		if a.Kind == "dns_update" {
			_, err := dnsdata.Parse(a.Name, a.Type, a.OldValue)
			return err
		}
	case "ldap_add":
		if !directory.InScope(a.Parent, settings.BaseDN) {
			return errors.New("LDAP add outside configured base")
		}
		_, err := directory.BuildAdd(a.EntryKind, a.Parent, a.Name, a.Attributes)
		return err
	case "ldap_modify", "ldap_delete", "ldap_disable":
		if !directory.InScope(a.DN, settings.BaseDN) {
			return errors.New("LDAP target outside configured base")
		}
		if _, err := directory.Assertion(a.Revision, nil); err != nil {
			return err
		}
		if a.Kind == "ldap_delete" && directory.EqualDN(a.DN, settings.BaseDN) {
			return errors.New("refusing to delete LDAP base")
		}
		if a.Kind == "ldap_modify" {
			return directory.ValidateChanges(a.EntryKind, a.Attributes)
		}
	default:
		return errors.New("invalid write action")
	}
	return nil
}

func (p Plan) Preview() string {
	var text strings.Builder
	text.WriteString(p.Title + "\n")
	for _, a := range p.Actions {
		a.Zone = fmt.Sprintf("%q", a.Zone)
		a.Name = fmt.Sprintf("%q", a.Name)
		a.Value = fmt.Sprintf("%q", a.Value)
		a.OldValue = fmt.Sprintf("%q", a.OldValue)
		a.DN = fmt.Sprintf("%q", a.DN)
		a.Parent = fmt.Sprintf("%q", a.Parent)
		switch a.Kind {
		case "dns_add":
			fmt.Fprintf(&text, "Add %s: %s %s %s (TTL 900s)\n", a.Zone, a.Name, a.Type, a.Value)
		case "dns_update":
			fmt.Fprintf(&text, "Update %s: %s %s\nOld: %s\nNew: %s\n", a.Zone, a.Name, a.Type, a.OldValue, a.Value)
		case "dns_delete":
			fmt.Fprintf(&text, "Delete %s: %s %s %s\n", a.Zone, a.Name, a.Type, a.Value)
		case "ldap_add":
			fmt.Fprintf(&text, "Add %s %s below %s\n", a.EntryKind, a.Name, a.Parent)
		case "ldap_modify":
			fmt.Fprintf(&text, "Modify %s at revision %s\n", a.DN, a.Revision)
			keys := []string{}
			for k := range a.Attributes {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(&text, "%q = %q\n", k, a.Attributes[k])
			}
		case "ldap_delete":
			fmt.Fprintf(&text, "DELETE %s at revision %s\n", a.DN, a.Revision)
		case "ldap_disable":
			fmt.Fprintf(&text, "Disable %s at revision %s; UAC %d -> %d\n", a.DN, a.Revision, a.Flags, a.Flags|2)
		}
	}
	text.WriteString("No rollback. No automatic retry. Partial/unknown outcomes require inspection.")
	return text.String()
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

func (Native) Execute(ctx context.Context, settings config.Settings, plan Plan) lifecycle.Outcome {
	return executePlan(ctx, settings, plan, executeAction)
}

// executePlan owns sequencing. Actions are never retried, and a later failure
// cannot erase earlier acknowledged writes.
func executePlan(
	ctx context.Context,
	settings config.Settings,
	plan Plan,
	execute func(context.Context, config.Settings, Action) error,
) lifecycle.Outcome {
	if err := ctx.Err(); err != nil {
		return lifecycle.Outcome{Err: err}
	}
	if err := plan.Validate(settings); err != nil {
		return lifecycle.Outcome{Err: err}
	}
	plan = plan.Clone()
	for index, action := range plan.Actions {
		if err := ctx.Err(); err != nil {
			return lifecycle.Outcome{Err: err, Uncertain: index > 0}
		}
		if err := execute(ctx, settings, action); err != nil {
			var dnsUnknown *dnsrpc.UncertainError
			var ldapUnknown *directory.UncertainError
			uncertain := index > 0 || errors.As(err, &dnsUnknown) || errors.As(err, &ldapUnknown)
			return lifecycle.Outcome{
				Err: fmt.Errorf("%d of %d operations acknowledged before failure: %w",
					index, len(plan.Actions), err),
				Uncertain: uncertain,
			}
		}
	}
	return lifecycle.Outcome{}
}

func executeAction(ctx context.Context, settings config.Settings, action Action) error {
	client := directory.New(settings.LDAP())
	switch action.Kind {
	case "dns_add", "dns_update", "dns_delete":
		return executeDNS(ctx, settings, action)
	case "ldap_add":
		_, err := client.Add(ctx, action.EntryKind, action.Parent, action.Name, action.Attributes)
		return err
	case "ldap_modify":
		return client.Modify(ctx, action.DN, action.EntryKind, action.Revision, action.Attributes)
	case "ldap_delete":
		return client.Delete(ctx, action.DN, action.Revision)
	case "ldap_disable":
		return client.Disable(ctx, action.DN, action.Revision, action.Flags)
	default:
		panic("validated write action has unknown kind")
	}
}

func executeDNS(ctx context.Context, settings config.Settings, action Action) error {
	var original, replacement *record.Record
	var err error
	switch action.Kind {
	case "dns_add":
		replacement, err = encodeDNS(action, action.Value)
	case "dns_delete":
		original, err = encodeDNS(action, action.Value)
	case "dns_update":
		original, err = encodeDNS(action, action.OldValue)
		if err == nil {
			replacement, err = encodeDNS(action, action.Value)
		}
	default:
		panic("non-DNS action passed to executeDNS")
	}
	if err != nil {
		return err
	}
	client, err := dnsrpc.Dial(ctx, settings.DNS())
	if err != nil {
		return err
	}
	defer client.Close()

	if action.Kind == "dns_update" {
		return client.Replace(ctx, action.Zone, action.Name, original, replacement)
	}
	return client.Mutate(ctx, action.Zone, action.Name, original, replacement)
}

func encodeDNS(action Action, value string) (*record.Record, error) {
	resource, err := dnsdata.Parse(action.Name, action.Type, value)
	if err != nil {
		return nil, err
	}
	return dnsrpc.Encode(resource)
}

// Inspect never writes, and never clears the write guard itself. A missing
// target is reported as absence, not interpreted as cancellation or rollback.
func Inspect(ctx context.Context, service Service, s config.Settings, p Plan) (string, error) {
	var report strings.Builder
	report.WriteString(p.Preview() + "\nObserved state on original DC:\n")
	for _, a := range p.Actions {
		if a.Zone != "" {
			rows, e := service.Records(ctx, s, a.Zone, a.Name, dns.TypeANY)
			if e != nil {
				var st *dnsrpc.StatusError
				if !errors.As(e, &st) || st.Code != 9714 {
					return "", e
				}
			}
			fmt.Fprintf(&report, "%s:%s — %d returned records\n", a.Zone, a.Name, len(rows))
			for _, r := range rows {
				fmt.Fprintf(&report, "%s %s %s\n", r.Name, r.Type, r.Value)
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
			fmt.Fprintf(&report, "%s — %d returned entries\n", dn, len(rows))
			for _, r := range rows {
				fmt.Fprintf(&report, "revision=%s UAC=%s description=%s mail=%s\n", r.Revision, r.First("userAccountControl"), r.First("description"), r.First("mail"))
			}
		}
	}
	return report.String(), nil
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
