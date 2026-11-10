package backend

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/dnsdata"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
	"github.com/lauritsk/sambatui/internal/invariant"
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

type Service interface {
	Zones(context.Context, config.Settings) ([]string, error)
	Records(context.Context, config.Settings, string, string, uint16) ([]dnsrpc.Row, error)
	Search(context.Context, config.Settings, string, string, string, int) ([]directory.Entry, error)
	Execute(context.Context, config.Settings, Plan) lifecycle.Outcome
}
type Native struct{}

func (Native) Zones(operationContext context.Context, settings config.Settings) ([]string, error) {
	client, err := dnsrpc.Dial(operationContext, settings.DNS())
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.Zones(operationContext)
}

func (Native) Records(
	operationContext context.Context,
	settings config.Settings,
	zone, node string,
	recordType uint16,
) ([]dnsrpc.Row, error) {
	client, err := dnsrpc.Dial(operationContext, settings.DNS())
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.Records(operationContext, zone, node, recordType)
}

func (Native) Search(
	operationContext context.Context,
	settings config.Settings,
	base, kind, text string,
	limit int,
) ([]directory.Entry, error) {
	return directory.New(settings.LDAP()).Search(operationContext, base, kind, text, limit)
}

func (Native) Execute(
	operationContext context.Context,
	settings config.Settings,
	plan Plan,
) lifecycle.Outcome {
	return executePlan(operationContext, settings, plan, executeAction)
}

// executePlan owns sequencing. Actions are never retried, and a later failure
// cannot erase earlier acknowledged writes.
func executePlan(
	operationContext context.Context,
	settings config.Settings,
	plan Plan,
	execute func(context.Context, config.Settings, Action) error,
) lifecycle.Outcome {
	invariant.Require(operationContext != nil, "write plan requires a context")
	invariant.Require(execute != nil, "write plan requires a dispatcher")
	if err := operationContext.Err(); err != nil {
		return lifecycle.Outcome{Err: err}
	}
	if err := plan.Validate(settings); err != nil {
		return lifecycle.Outcome{Err: err}
	}
	plan = plan.Clone()
	for index, action := range plan.Actions {
		if err := operationContext.Err(); err != nil {
			return lifecycle.Outcome{Err: err, Uncertain: index > 0}
		}
		if err := execute(operationContext, settings, action); err != nil {
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

func executeAction(
	operationContext context.Context,
	settings config.Settings,
	action Action,
) error {
	client := directory.New(settings.LDAP())
	switch action.Kind {
	case "dns_add", "dns_update", "dns_delete":
		return executeDNS(operationContext, settings, action)
	case "ldap_add":
		_, err := client.Add(
			operationContext,
			action.EntryKind,
			action.Parent,
			action.Name,
			action.Attributes,
		)
		return err
	case "ldap_modify":
		return client.Modify(
			operationContext,
			action.DN,
			action.EntryKind,
			action.Revision,
			action.Attributes,
		)
	case "ldap_delete":
		return client.Delete(operationContext, action.DN, action.Revision)
	case "ldap_disable":
		return client.Disable(operationContext, action.DN, action.Revision, action.Flags)
	default:
		panic("validated write action has unknown kind")
	}
}

func executeDNS(operationContext context.Context, settings config.Settings, action Action) error {
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
	client, err := dnsrpc.Dial(operationContext, settings.DNS())
	if err != nil {
		return err
	}
	defer client.Close()

	if action.Kind == "dns_update" {
		return client.Replace(operationContext, action.Zone, action.Name, original, replacement)
	}
	return client.Mutate(operationContext, action.Zone, action.Name, original, replacement)
}

func encodeDNS(action Action, value string) (*record.Record, error) {
	resource, err := dnsdata.Parse(action.Name, action.Type, value)
	if err != nil {
		return nil, err
	}
	return dnsrpc.Encode(resource)
}

func ParseQueryType(text string) (uint16, error) {
	text = strings.ToUpper(text)
	if text == "" || text == "ALL" {
		return dns.TypeANY, nil
	}
	if number, ok := dns.StringToType[text]; ok {
		return number, nil
	}
	return 0, errors.New("invalid DNS query type")
}
