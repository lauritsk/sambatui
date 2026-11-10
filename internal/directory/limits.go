package directory

import (
	"errors"

	"github.com/go-ldap/ldap/v3"
	"github.com/lauritsk/sambatui/internal/invariant"
)

const (
	searchBytesMax     = 16 << 20
	entryAttributesMax = 128
	dnBytesMax         = 64 << 10
	filterBytesMax     = 1 << 20
)

// Include slice/map overhead so empty strings cannot bypass the byte budget.
// The same budget follows initial entries and every range continuation.
type readBudget struct{ remainingBytes int }

func newReadBudget() *readBudget {
	return &readBudget{remainingBytes: searchBytesMax}
}

func (budget *readBudget) take(sizeBytes int) error {
	invariant.Require(sizeBytes >= 0, "negative LDAP budget consumption")
	invariant.Require(budget.remainingBytes >= 0, "LDAP budget underflow")
	if sizeBytes > budget.remainingBytes {
		return errors.New("LDAP search exceeds byte safety limit; no partial result returned")
	}
	budget.remainingBytes -= sizeBytes
	return nil
}

func (budget *readBudget) entry(entry *ldap.Entry) error {
	if entry == nil {
		return errors.New("missing LDAP entry")
	}
	if len(entry.Attributes) > entryAttributesMax {
		return errors.New("LDAP entry exceeds attribute safety limit")
	}
	if err := budget.take(len(entry.DN)); err != nil {
		return err
	}
	for _, attribute := range entry.Attributes {
		if attribute == nil {
			return errors.New("missing LDAP attribute")
		}
		if err := budget.take(64); err != nil {
			return err
		}
		if err := budget.take(len(attribute.Name)); err != nil {
			return err
		}
		for _, value := range attribute.Values {
			if err := budget.take(16); err != nil {
				return err
			}
			if err := budget.take(len(value)); err != nil {
				return err
			}
		}
	}
	return nil
}
