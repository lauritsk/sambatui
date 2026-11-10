package backend

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/dnsdata"
)

func (plan Plan) Clone() Plan {
	if err := plan.validateSize(); err != nil {
		panic("cannot clone unbounded write plan: " + err.Error())
	}
	out := Plan{Title: plan.Title, Actions: append([]Action(nil), plan.Actions...)}
	for index, action := range out.Actions {
		if action.Attributes != nil {
			attributes := map[string]string{}
			for key, value := range action.Attributes {
				attributes[key] = value
			}
			out.Actions[index].Attributes = attributes
		}
	}
	return out
}

func (plan Plan) Validate(settings config.Settings) error {
	if err := plan.validateSize(); err != nil {
		return err
	}
	if len(plan.Actions) == 0 {
		return errors.New("empty write plan")
	}
	if len(plan.Actions) > MaxActions {
		return fmt.Errorf("write plan exceeds %d actions", MaxActions)
	}
	for _, action := range plan.Actions {
		if err := action.validate(settings); err != nil {
			return err
		}
	}
	return nil
}

func (action Action) validate(settings config.Settings) error {
	switch action.Kind {
	case "dns_add", "dns_delete", "dns_update":
		if !dnsdata.ValidName(action.Zone, false) {
			return errors.New("invalid DNS zone")
		}
		if _, err := dnsdata.Parse(action.Name, action.Type, action.Value); err != nil {
			return err
		}
		if action.Kind == "dns_update" {
			_, err := dnsdata.Parse(action.Name, action.Type, action.OldValue)
			return err
		}
	case "ldap_add":
		if !directory.InScope(action.Parent, settings.BaseDN) {
			return errors.New("LDAP add outside configured base")
		}
		_, err := directory.BuildAdd(
			action.EntryKind,
			action.Parent,
			action.Name,
			action.Attributes,
		)
		return err
	case "ldap_modify", "ldap_delete", "ldap_disable":
		if !directory.InScope(action.DN, settings.BaseDN) {
			return errors.New("LDAP target outside configured base")
		}
		if _, err := directory.Assertion(action.Revision, nil); err != nil {
			return err
		}
		if action.Kind == "ldap_delete" && directory.EqualDN(action.DN, settings.BaseDN) {
			return errors.New("refusing to delete LDAP base")
		}
		if action.Kind == "ldap_modify" {
			return directory.ValidateChanges(action.EntryKind, action.Attributes)
		}
	default:
		return errors.New("invalid write action")
	}
	return nil
}

func (plan Plan) Preview() string {
	if err := plan.validateSize(); err != nil {
		panic("cannot preview unbounded write plan: " + err.Error())
	}
	var text strings.Builder
	text.WriteString(plan.Title + "\n")
	for _, action := range plan.Actions {
		action.Zone = fmt.Sprintf("%q", action.Zone)
		action.Name = fmt.Sprintf("%q", action.Name)
		action.Value = fmt.Sprintf("%q", action.Value)
		action.OldValue = fmt.Sprintf("%q", action.OldValue)
		action.DN = fmt.Sprintf("%q", action.DN)
		action.Parent = fmt.Sprintf("%q", action.Parent)
		switch action.Kind {
		case "dns_add":
			fmt.Fprintf(
				&text,
				"Add %s: %s %s %s (TTL 900s)\n",
				action.Zone,
				action.Name,
				action.Type,
				action.Value,
			)
		case "dns_update":
			fmt.Fprintf(
				&text,
				"Update %s: %s %s\nOld: %s\nNew: %s\n",
				action.Zone,
				action.Name,
				action.Type,
				action.OldValue,
				action.Value,
			)
		case "dns_delete":
			fmt.Fprintf(
				&text,
				"Delete %s: %s %s %s\n",
				action.Zone,
				action.Name,
				action.Type,
				action.Value,
			)
		case "ldap_add":
			fmt.Fprintf(&text, "Add %s %s below %s\n", action.EntryKind, action.Name, action.Parent)
		case "ldap_modify":
			fmt.Fprintf(&text, "Modify %s at revision %s\n", action.DN, action.Revision)
			previewAttributes(&text, action.Attributes)
		case "ldap_delete":
			fmt.Fprintf(&text, "DELETE %s at revision %s\n", action.DN, action.Revision)
		case "ldap_disable":
			fmt.Fprintf(
				&text,
				"Disable %s at revision %s; UAC %d -> %d\n",
				action.DN,
				action.Revision,
				action.Flags,
				action.Flags|2,
			)
		}
	}
	text.WriteString(
		"No rollback. No automatic retry. Partial/unknown outcomes require inspection.",
	)
	return text.String()
}

func previewAttributes(text *strings.Builder, attributes map[string]string) {
	keys := make([]string, 0, len(attributes))
	for key := range attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(text, "%q = %q\n", key, attributes[key])
	}
}
