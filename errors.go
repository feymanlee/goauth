package goauth

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidConfig     = errors.New("invalid configuration")
	ErrInvalidCredential = errors.New("invalid credential")
	ErrProvider          = errors.New("provider rejected request")
	ErrTransport         = errors.New("transport failure")
	ErrResponse          = errors.New("invalid provider response")
	ErrIdentityMismatch  = errors.New("identity or application mismatch")
	ErrSignature         = errors.New("invalid response signature")
)

type Error struct {
	Provider   Provider
	Operation  string
	Kind       error
	Code       string
	StatusCode int
}

func (failure *Error) Error() string {
	message := fmt.Sprintf("goauth %s %s: %v", failure.Provider, failure.Operation, failure.Kind)
	if failure.Code != "" {
		message += " (code=" + failure.Code + ")"
	}
	if failure.StatusCode != 0 {
		message += fmt.Sprintf(" (http=%d)", failure.StatusCode)
	}
	return message
}

func (failure *Error) Unwrap() error {
	return failure.Kind
}
