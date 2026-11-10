package directory

import "errors"

// Direct callers receive the same bounds as plans, before escaping or copying.
func validateAddSize(parent, name string, attributes map[string]string) error {
	if len(parent) > dnBytesMax || len(name) > dnBytesMax {
		return errors.New("LDAP add name or parent exceeds safety limit")
	}
	if len(attributes) > 32 {
		return errors.New("LDAP add exceeds attribute safety limit")
	}
	remainingBytes := filterBytesMax
	for attribute, value := range attributes {
		if len(attribute) > remainingBytes {
			return errors.New("LDAP add exceeds byte safety limit")
		}
		remainingBytes -= len(attribute)
		if len(value) > remainingBytes {
			return errors.New("LDAP add exceeds byte safety limit")
		}
		remainingBytes -= len(value)
	}
	return nil
}
