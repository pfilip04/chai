package errs

import (
	"errors"
)

var (
	AuthError     = errors.New("Unauthorized")
	DatabaseError = errors.New("Database failed")
)
