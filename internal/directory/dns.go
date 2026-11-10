package directory

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/lauritsk/sambatui/internal/dnsdata"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
	"github.com/miekg/dns"
)

const dnsNodesMax = 10000

// DNSRecords reads only the selected zone on this DC, over the configured verified TLS session.
func (client *Client) DNSRecords(
	operationContext context.Context, zone, node string, recordType uint16,
) ([]dnsrpc.Row, error) {
	if !dnsdata.ValidName(zone, false) || (node != "" && !dnsdata.ValidName(node, true)) {
		return nil, errors.New("invalid directory DNS target")
	}
	zone = strings.TrimSuffix(zone, ".")
	target, err := dnsRelativeNode(zone, node)
	if err != nil {
		return nil, err
	}
	filter := "(&(objectClass=dnsNode)(!(dNSTombstoned=TRUE))"
	if target != "@" {
		escaped := ldap.EscapeFilter(target)
		filter += "(|(name=" + escaped + ")(name=*." + escaped + "))"
	}
	filter += ")"
	var rows []dnsrpc.Row
	err = client.with(operationContext, func(session Session) error {
		zoneDN, err := dnsZoneDN(session, zone)
		if err != nil {
			return err
		}
		request := ldap.NewSearchRequest(zoneDN, ldap.ScopeSingleLevel, ldap.NeverDerefAliases,
			0, 0, false, filter, []string{"name", "dnsRecord", "dNSTombstoned"}, nil)
		entries, err := searchPagesBounded(operationContext, session, request,
			searchPageDefault, 0, dnsNodesMax)
		if err != nil {
			return err
		}
		rows, err = dnsRows(zone, target, entries, recordType)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("DNS directory enumeration: %w", err)
	}
	return rows, nil
}

func dnsRelativeNode(zone, node string) (string, error) {
	if node == "" || node == "@" || strings.EqualFold(strings.TrimSuffix(node, "."), zone) {
		return "@", nil
	}
	name := strings.TrimSuffix(node, ".")
	suffix := "." + zone
	if strings.HasSuffix(strings.ToLower(name), strings.ToLower(suffix)) {
		return name[:len(name)-len(suffix)], nil
	}
	if strings.HasSuffix(node, ".") {
		return "", errors.New("absolute DNS node is outside the selected zone")
	}
	return name, nil
}

func dnsZoneDN(session Session, zone string) (string, error) {
	budget := newReadBudget()
	root, err := dnsBase(session, "", []string{"namingContexts", "defaultNamingContext"}, budget)
	if err != nil {
		return "", err
	}
	if root == nil {
		return "", errors.New("DNS directory discovery returned no RootDSE")
	}
	contexts := root.GetAttributeValues("namingContexts")
	if len(contexts) == 0 || len(contexts) > 32 {
		return "", errors.New("invalid DNS directory naming contexts")
	}
	found := ""
	for _, namingContext := range contexts {
		if len(namingContext) > dnBytesMax || !InScope(namingContext, namingContext) {
			return "", errors.New("invalid DNS directory naming context")
		}
		containers := []string{"CN=MicrosoftDNS," + namingContext}
		if strings.EqualFold(namingContext, root.GetAttributeValue("defaultNamingContext")) {
			containers = append(containers, "CN=MicrosoftDNS,CN=System,"+namingContext)
		}
		for _, container := range containers {
			distinguishedName := "DC=" + ldap.EscapeDN(zone) + "," + container
			entry, err := dnsBase(session, distinguishedName, []string{"objectClass"}, budget)
			if err != nil {
				return "", err
			}
			if entry == nil {
				continue
			}
			if found != "" || !dnsZoneClass(entry) {
				return "", errors.New("ambiguous or invalid DNS directory zone")
			}
			found = entry.DN
		}
	}
	if found == "" {
		return "", errors.New("selected DNS zone was not found in this DC's directory partitions")
	}
	return found, nil
}

func dnsZoneClass(entry *ldap.Entry) bool {
	for _, class := range entry.GetAttributeValues("objectClass") {
		if strings.EqualFold(class, "dnsZone") {
			return true
		}
	}
	return false
}

func dnsBase(
	session Session, base string, attributes []string, budget *readBudget,
) (*ldap.Entry, error) {
	result, err := session.Search(ldap.NewSearchRequest(base, ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", attributes, nil))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if result == nil || len(result.Referrals) > 0 || len(result.Entries) != 1 {
		return nil, errors.New("invalid or referred DNS directory lookup")
	}
	entry := result.Entries[0]
	if err := budget.entry(entry); err != nil {
		return nil, err
	}
	if (base == "" && entry.DN != "") || (base != "" &&
		(!InScope(entry.DN, base) || !InScope(base, entry.DN))) {
		return nil, errors.New("DNS directory lookup returned a different target")
	}
	return entry, nil
}

func dnsRows(zone, target string, entries []Entry, recordType uint16) ([]dnsrpc.Row, error) {
	rows := []dnsrpc.Row{}
	for _, entry := range entries {
		name := entry.First("name")
		if len(entry.Attributes["name"]) != 1 || name == "" || len(name) > 253 ||
			strings.ContainsRune(name, 0) ||
			strings.EqualFold(entry.First("dnstombstoned"), "TRUE") {
			return nil, errors.New("invalid or tombstoned directory DNS node")
		}
		if target != "@" && !strings.EqualFold(name, target) &&
			!strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(target)) {
			return nil, errors.New("DNS directory returned a node outside the selected subtree")
		}
		for _, value := range entry.Attributes["dnsrecord"] {
			if len(value) < 24 || len(value) > 24+65535 {
				return nil, errors.New("invalid directory DNS record size")
			}
			data := []byte(value)
			if recordType != 0 && recordType != dns.TypeANY &&
				binary.LittleEndian.Uint16(data[2:4]) != recordType {
				continue
			}
			row, err := dnsrpc.DirectoryRecord(zone, name, data)
			if err != nil {
				return nil, err
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}
