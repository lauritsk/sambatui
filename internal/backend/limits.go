package backend

import "errors"

const (
	// Bound input before cloning, escaping confirmation text, or JSON encoding.
	// Escaping can expand one byte to six; the input budget keeps this predictable.
	planBytesMax        = 1 << 20
	actionAttributesMax = 32
)

func (plan Plan) validateSize() error {
	if len(plan.Actions) > MaxActions {
		return errors.New("write plan exceeds action safety limit")
	}
	remainingBytes := planBytesMax
	if len(plan.Title) > remainingBytes {
		return errors.New("write plan exceeds byte safety limit")
	}
	remainingBytes -= len(plan.Title)
	for _, action := range plan.Actions {
		if len(action.Attributes) > actionAttributesMax {
			return errors.New("write action exceeds attribute safety limit")
		}
		for _, value := range []string{
			action.Kind, action.Zone, action.Name, action.Type, action.Value,
			action.OldValue, action.DN, action.Revision, action.EntryKind, action.Parent,
		} {
			if len(value) > remainingBytes {
				return errors.New("write plan exceeds byte safety limit")
			}
			remainingBytes -= len(value)
		}
		for attribute, value := range action.Attributes {
			if len(attribute) > remainingBytes {
				return errors.New("write plan exceeds byte safety limit")
			}
			remainingBytes -= len(attribute)
			if len(value) > remainingBytes {
				return errors.New("write plan exceeds byte safety limit")
			}
			remainingBytes -= len(value)
		}
	}
	return nil
}
