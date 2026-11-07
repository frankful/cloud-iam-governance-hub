// Package apperr provides application-level error classification so that
// handlers can map errors to HTTP statuses without pattern-matching on
// message text.
//
// History: ticket validation errors used to be classified by message
// prefix whitelist in the handler (isValidationError). Every new
// user-facing validation message had to be added to that list, and
// forgetting it silently degraded the response to a 500 (four separate
// incidents). Structured errors fix this at the source: service code
// wraps user-actionable failures with ValidationError and the handler
// detects the type via errors.As, independent of wording.
package apperr

import (
	"errors"
	"fmt"
)

// ValidationError marks a failure caused by the caller's input or by
// mutable business state (duplicate resource, ticket conflict, missing
// approver binding, ...). Handlers should map it to 400 Bad Request and
// surface Error() to the user.
//
// Use Validation/Validationf at creation sites. Do not wrap internal
// failures (DB down, upstream 5xx) with it.
type ValidationError struct {
	// msg carries a fully formed message (Validation), or...
	msg string
	// wrapped carries a formatted error chain (Validationf, supports %w).
	wrapped error
}

// Validation returns a ValidationError carrying msg verbatim.
// Use it when the message is fully formed (no format verbs).
func Validation(msg string) error {
	return &ValidationError{msg: msg}
}

// Validationf returns a ValidationError formatted like fmt.Errorf,
// including support for the %w verb to wrap a cause.
func Validationf(format string, args ...any) error {
	return &ValidationError{wrapped: fmt.Errorf(format, args...)}
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	if e.wrapped != nil {
		return e.wrapped.Error()
	}
	return e.msg
}

// Unwrap exposes the wrapped cause for errors.Is/As chains.
func (e *ValidationError) Unwrap() error {
	return e.wrapped
}

// IsValidationError reports whether err (or any error in its chain) is a
// *ValidationError. Handlers should treat it as a 4xx client error.
func IsValidationError(err error) bool {
	var target *ValidationError
	return errors.As(err, &target)
}
