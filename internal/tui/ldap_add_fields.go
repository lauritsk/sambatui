package tui

import "github.com/lauritsk/sambatui/internal/invariant"

const (
	ldapAddKindField = iota
	ldapAddParentField
	ldapAddNameField
	ldapAddAccountField
	ldapAddDescriptionField
	ldapAddMailField
	ldapAddDisplayField
	ldapAddHostnameField
	ldapAddPrincipalField
	ldapAddFieldCount
)

func ldapAddFieldVisible(kind string, index int) bool {
	if index <= ldapAddNameField || index == ldapAddDescriptionField {
		return true
	}
	if kind == "ou" {
		return false
	}
	switch index {
	case ldapAddHostnameField:
		return kind == "computer"
	case ldapAddPrincipalField:
		return kind == "user"
	default:
		return true
	}
}

func ldapAddFieldIndices(fields []field) []int {
	invariant.Require(len(fields) == ldapAddFieldCount, "LDAP add field layout changed")
	kind := fields[ldapAddKindField].text()
	indices := make([]int, 0, len(fields))
	for index := range fields {
		if ldapAddFieldVisible(kind, index) {
			indices = append(indices, index)
		}
	}
	return indices
}

func ldapAddAttributes(values []string) map[string]string {
	invariant.Require(len(values) == ldapAddFieldCount, "LDAP add values changed")
	kind := values[ldapAddKindField]
	keys := [ldapAddFieldCount]string{
		ldapAddAccountField: "sAMAccountName", ldapAddDescriptionField: "description",
		ldapAddMailField: "mail", ldapAddDisplayField: "displayName",
		ldapAddHostnameField: "dNSHostName", ldapAddPrincipalField: "userPrincipalName",
	}
	attributes := make(map[string]string, ldapAddFieldCount-3)
	for index := ldapAddAccountField; index < len(keys); index++ {
		if ldapAddFieldVisible(kind, index) && values[index] != "" {
			attributes[keys[index]] = values[index]
		}
	}
	return attributes
}
