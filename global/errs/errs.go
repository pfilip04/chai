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
		Err:    errors.New("Bad Request Error"),
		Status: http.StatusBadRequest,
	}

	NotAcceptableError = Err{
		Err:    errors.New("Not Acceptable Error"),
		Status: http.StatusNotAcceptable,
	}

	ConflictError = Err{
		Err:    errors.New("Conflict Error"),
		Status: http.StatusConflict,
	}

	RequestTimeoutError = Err{
		Err:    errors.New("Request Timeout Error"),
		Status: http.StatusRequestTimeout,
	}

	TooManyRequestsError = Err{
		Err:    errors.New("Too Many Requests Error"),
		Status: http.StatusTooManyRequests,
	}
)
