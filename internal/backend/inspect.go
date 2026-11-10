package backend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
	"github.com/lauritsk/sambatui/internal/invariant"
	"github.com/miekg/dns"
)

const reportBytesMax = 16 << 20

// Inspect never writes. A missing target is absence, not cancellation or rollback.
// Bound aggregate output across all actions, not just each protocol response.
func Inspect(
	ctx context.Context, service Service, settings config.Settings, plan Plan,
) (string, error) {
	invariant.Require(ctx != nil, "inspection requires a context")
	invariant.Require(service != nil, "inspection requires a backend")
	if err := plan.Validate(settings); err != nil {
		return "", err
	}
	report := &inspectionReport{}
	if _, err := fmt.Fprintf(
		report,
		"%s\nObserved state on original DC:\n",
		plan.Preview(),
	); err != nil {
		return "", err
	}
	for _, action := range plan.Actions {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		var err error
		if action.Zone != "" {
			err = inspectDNS(ctx, service, settings, action, report)
		} else {
			err = inspectLDAP(ctx, service, settings, action, report)
		}
		if err != nil {
			return "", err
		}
	}
	return report.text.String(), nil
}

type inspectionReport struct{ text strings.Builder }

func (report *inspectionReport) Write(data []byte) (int, error) {
	invariant.Require(report.text.Len() <= reportBytesMax, "inspection report exceeded budget")
	if len(data) > reportBytesMax-report.text.Len() {
		return 0, errors.New("inspection report exceeds 16 MiB; inspect fewer targets")
	}
	return report.text.Write(data)
}

func inspectDNS(
	ctx context.Context, service Service, settings config.Settings, action Action, report io.Writer,
) error {
	rows, err := service.Records(ctx, settings, action.Zone, action.Name, dns.TypeANY)
	if err != nil {
		var status *dnsrpc.StatusError
		if !errors.As(err, &status) || status.Code != 9714 {
			return err
		}
	}
	if _, err := fmt.Fprintf(report, "%s:%s — %d returned records\n",
		action.Zone, action.Name, len(rows)); err != nil {
		return err
	}
	for _, row := range rows {
		if _, err := fmt.Fprintf(report, "%s %s %s\n", row.Name, row.Type, row.Value); err != nil {
			return err
		}
	}
	return nil
}

func inspectLDAP(
	ctx context.Context, service Service, settings config.Settings, action Action, report io.Writer,
) error {
	dn := action.DN
	if action.Kind == "ldap_add" {
		request, err := directory.BuildAdd(
			action.EntryKind,
			action.Parent,
			action.Name,
			action.Attributes,
		)
		if err != nil {
			return err
		}
		dn = request.DN
	}
	rows, err := service.Search(ctx, settings, dn, "all", "", 0)
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return err
	}
	if _, err := fmt.Fprintf(report, "%s — %d returned entries\n", dn, len(rows)); err != nil {
		return err
	}
	for _, entry := range rows {
		if _, err := fmt.Fprintf(report, "revision=%s UAC=%s description=%s mail=%s\n",
			entry.Revision, entry.First("userAccountControl"),
			entry.First("description"), entry.First("mail")); err != nil {
			return err
		}
	}
	return nil
}
