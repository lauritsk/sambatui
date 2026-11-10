package dnsrpc

import "fmt"

// StatusError is a definite server refusal, unlike a transport failure after
// dispatch. Callers may use this distinction to avoid claiming rollback.
type StatusError struct {
	Operation string
	Code      int32
}

func (failure *StatusError) Error() string {
	detail := map[int32]string{
		5:    "access denied; check DNS administration permissions",
		87:   "invalid protocol parameter",
		234:  "more data available; incomplete enumeration refused",
		9711: "record already exists",
		9714: "record or zone does not exist",
		9601: "zone does not exist",
	}[failure.Code]
	if detail == "" {
		detail = "server refused the operation"
	}
	return fmt.Sprintf("DNS %s: %s (status %d)", failure.Operation, detail, failure.Code)
}

func statusError(op string, code int32) error {
	return &StatusError{op, code}
}

// UncertainError is produced only after entering the RPC write call. Connection,
// validation and read-before-update failures are not disguised as dispatched writes.
type UncertainError struct{ Cause error }

func (failure *UncertainError) Error() string {
	return "DNS write outcome uncertain; cancellation/lost response is " +
		"not rollback. Read server state before retrying: " +
		failure.Cause.Error()
}

func (failure *UncertainError) Unwrap() error {
	return failure.Cause
}
