package directory

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/lauritsk/sambatui/internal/invariant"
)

func Filter(kind, text string) (string, error) {
	if len(text) > filterBytesMax {
		return "", errors.New("LDAP search text exceeds safety limit")
	}
	base, ok := filters[kind]
	if !ok {
		return "", errors.New(
			"LDAP search kind must be users, groups, computers, ous, all " + "or containers",
		)
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return base, nil
	}
	needle := ldap.EscapeFilter(text)
	var builder strings.Builder
	builder.WriteString("(&" + base + "(|")
	for _, left := range []string{
		"cn",
		"name",
		"sAMAccountName",
		"userPrincipalName",
		"displayName",
		"mail",
		"proxyAddresses",
		"dNSHostName",
		"distinguishedName",
	} {
		builder.WriteString("(" + left + "=*" + needle + "*)")
	}
	builder.WriteString("))")
	return builder.String(), nil
}

func (entry Entry) First(name string) string {
	values := entry.Attributes[strings.ToLower(name)]
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

func normalize(entry *ldap.Entry) Entry {
	out := Entry{DN: entry.DN, Attributes: map[string][]string{}}
	for _, attribute := range entry.Attributes {
		key := strings.ToLower(attribute.Name)
		out.Attributes[key] = append(out.Attributes[key], attribute.Values...)
	}
	classes := out.Attributes["objectclass"]
	out.Kind = "object"
	for _, currentKey := range []string{"user", "group", "computer", "organizationalUnit"} {
		for _, value := range classes {
			if strings.EqualFold(value, currentKey) {
				out.Kind = currentKey
			}
		}
	}
	if out.Kind == "organizationalUnit" {
		out.Kind = "ou"
	}
	out.Name = out.First("name")
	if out.Name == "" {
		out.Name = out.First("cn")
	}
	if values := out.Attributes["usnchanged"]; len(values) == 1 && decimal(values[0]) {
		out.Revision = values[0]
	}
	return out
}

func (client *Client) Search(
	operationContext context.Context,
	base, kind, text string,
	limit int,
) ([]Entry, error) {
	if limit < 0 || limit > searchRowsMax {
		return nil, fmt.Errorf("LDAP row limit must be 0–%d", searchRowsMax)
	}
	if base == "" {
		base = client.settings.BaseDN
	}
	if !InScope(base, client.settings.BaseDN) {
		return nil, errors.New("LDAP search base outside configured scope")
	}
	filter, err := Filter(kind, text)
	if err != nil {
		return nil, err
	}
	scope := ldap.ScopeWholeSubtree
	if kind == "containers" {
		scope = ldap.ScopeSingleLevel
	}
	pageSize := client.settings.PageSize
	if pageSize == 0 {
		pageSize = searchPageDefault
	}
	if pageSize > searchRowsMax {
		return nil, errors.New("LDAP page size exceeds read safety limit")
	}
	request := ldap.NewSearchRequest(
		base, scope, ldap.NeverDerefAliases, 0, 0, false, filter,
		append([]string(nil), Attributes...), nil,
	)
	var rows []Entry
	err = client.with(operationContext, func(session Session) error {
		var err error
		rows, err = searchPages(operationContext, session, request, pageSize, limit)
		return err
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func searchPages(
	operationContext context.Context, session Session, request *ldap.SearchRequest,
	pageSize uint32, limit int,
) ([]Entry, error) {
	return searchPagesBounded(operationContext, session, request, pageSize, limit, searchRowsMax)
}

func searchPagesBounded(
	operationContext context.Context, session Session, request *ldap.SearchRequest,
	pageSize uint32, limit, rowsMax int,
) ([]Entry, error) {
	invariant.Require(rowsMax > 0 && rowsMax <= dnsNodesMax, "invalid LDAP row budget")
	invariant.Require(limit >= 0 && limit <= rowsMax, "invalid LDAP caller limit")
	control := ldap.NewControlPaging(pageSize)
	request.Controls = []ldap.Control{
		control, ldap.NewControlString(ldap.ControlTypeMicrosoftDomainScope, true, ""),
	}
	capacity := rowsMax
	if limit > 0 {
		capacity = limit
	}
	rows := make([]Entry, 0, capacity)
	budget := newReadBudget()
	for page := 0; page < searchPagesMax; page++ {
		if err := operationContext.Err(); err != nil {
			return nil, err
		}
		result, err := session.Search(request)
		if err != nil {
			return nil, fmt.Errorf("LDAP search: %w", err)
		}
		if result == nil {
			return nil, errors.New("LDAP search returned no result")
		}
		if len(result.Referrals) > 0 {
			return nil, errors.New(
				"LDAP search returned referrals; select the appropriate individual DC",
			)
		}
		for _, entry := range result.Entries {
			if entry == nil || !InScope(entry.DN, request.BaseDN) {
				return nil, errors.New(
					"LDAP server returned an entry outside the selected search scope",
				)
			}
			// A zero caller limit requests a complete result, not unbounded memory.
			if len(rows) == rowsMax {
				return nil, errors.New("LDAP row safety limit exceeded; no partial result returned")
			}
			if err := expandRangesBudget(operationContext, session, entry, budget); err != nil {
				return nil, err
			}
			rows = append(rows, normalize(entry))
			if limit > 0 && len(rows) == limit {
				return rows, nil
			}
		}
		paging := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		if paging == nil {
			return rows, nil
		}
		next, ok := paging.(*ldap.ControlPaging)
		if !ok || next == nil {
			return nil, errors.New("LDAP malformed paging control")
		}
		if len(next.Cookie) == 0 {
			return rows, nil
		}
		// Cookies are opaque: Samba may reuse the same handle on successive pages.
		if err := budget.take(len(next.Cookie)); err != nil {
			return nil, err
		}
		control.SetCookie(append([]byte(nil), next.Cookie...))
	}
	return nil, fmt.Errorf("LDAP paging exceeds %d pages", searchPagesMax)
}
