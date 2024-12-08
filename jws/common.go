package jws

import (
	"errors"
)

var (
	ErrHashUnavailable  = errors.New("hash unavailable")
	ErrInvalidSignature = errors.New("invalid signature")
)
