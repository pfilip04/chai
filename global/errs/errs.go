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
		Err:    errors.New("Database Failed"),
		Status: http.StatusConflict,
	}

	ServerError = Err{
		Err:    errors.New("Server Error"),
		Status: http.StatusInternalServerError,
	}

	LoadError = Err{
		Err:    errors.New("File Loading Error"),
		Status: http.StatusInternalServerError,
	}

	GenerationError = Err{
		Err:    errors.New("Generation Error"),
		Status: http.StatusInternalServerError,
	}
)
