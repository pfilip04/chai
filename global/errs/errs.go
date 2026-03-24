package errs

import (
	"errors"
	"net/http"
)

//
// Global Errors

var (
	AuthError = Err{
		Err:    errors.New("Unauthorized"),
		Status: http.StatusUnauthorized,
	}

	DatabaseError = Err{
		Err:    errors.New("Database Error"),
		Status: http.StatusInternalServerError,
	}

	ServerError = Err{
		Err:    errors.New("Server Error"),
		Status: http.StatusInternalServerError,
	}

	BadRequestError = Err{
		Err:    errors.New("Bad Request"),
		Status: http.StatusBadRequest,
	}

	NotAcceptableError = Err{
		Err:    errors.New("Not Acceptable"),
		Status: http.StatusNotAcceptable,
	}

	ForbiddenError = Err{
		Err:    errors.New("Forbidden"),
		Status: http.StatusForbidden,
	}

	ConflictError = Err{
		Err:    errors.New("Conflict"),
		Status: http.StatusConflict,
	}

	RequestTimeoutError = Err{
		Err:    errors.New("Request Timeout"),
		Status: http.StatusRequestTimeout,
	}

	TooManyRequestsError = Err{
		Err:    errors.New("Too Many Requests"),
		Status: http.StatusTooManyRequests,
	}
)
