package directory

import "strings"

// Compute defaults without modifying the caller's confirmation attributes.
func buildAddValues(kind, name string, attributes map[string]string) map[string]string {
	values := make(map[string]string, len(attributes)+3)
	for key, value := range attributes {
		if value != "" {
			values[key] = value
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
	return values
}
