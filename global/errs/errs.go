package errs

import (
	"errors"
	"net/http"
)

var (
	AuthError = Err{
		Err:    errors.New("Unauthorized"),
		Status: http.StatusUnauthorized,
	}
	DatabaseError = Err{
		Err:    errors.New("Database failed"),
		Status: http.StatusConflict,
	}
	ServerError = Err{
		Err:    errors.New("Server Error"),
		Status: http.StatusInternalServerError,
	}
)
