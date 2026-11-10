package tui

import (
	"reflect"
	"strings"
	"testing"
)

func TestHiddenLDAPFieldsCannotLeakIntoAnotherObjectKind(t *testing.T) {
	values := []string{
		"user", "DC=lab,DC=invalid", "Example", "account", "description",
		"mail@lab.invalid", "Display Name", "computer.lab.invalid", "user@lab.invalid",
	}
	user := ldapAddAttributes(values)
	if user["userPrincipalName"] == "" || user["dNSHostName"] != "" {
		t.Fatal("user creation includes the wrong schema fields", user)
	}
	values[0] = "group"
	group := ldapAddAttributes(values)
	if group["userPrincipalName"] != "" || group["dNSHostName"] != "" {
		t.Fatal("hidden account fields leaked into a group", group)
	}
	values[0] = "ou"
	if attributes := ldapAddAttributes(values); !reflect.DeepEqual(attributes,
		map[string]string{"description": "description"}) {
		t.Fatal("OU creation includes account-only fields", attributes)
	}
}

func TestAccountPreviewIncludesEnteredAttributesAndMissingPassword(t *testing.T) {
	model := testModel()
	model.setMode("ldap")
	model.writeForm("a")
	submit(model, "user", model.base, "Example", "example", "description", "example@lab.invalid", "Example User", "", "example@lab.invalid")
	if model.form == nil {
		t.Fatal("account creation skipped confirmation")
	}
	for _, value := range []string{"No password will be set", "userPrincipalName", "example@lab.invalid", "description"} {
		if !strings.Contains(model.form.Context, value) {
			t.Fatal("confirmation omitted", value)
		}
	}
	model.closeForm()
}
