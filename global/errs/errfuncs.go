package errs

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/pfilip04/chai/global/loggr"
)

func WriteError(w http.ResponseWriter, request string, err error, errmsg string, er Err) {

	if errors.Is(err, context.DeadlineExceeded) {

		loggr.Error("request timeout error",
			"request", request,
			"message", errmsg,
			"error", err,
			"status", RequestTimeoutError.Status)
		http.Error(w, RequestTimeoutError.Err.Error(), RequestTimeoutError.Status)
		return
	}

	loggr.Error("request error",
		"request", request,
		"message", errmsg,
		"error", err,
		"status", er.Status)
	http.Error(w, er.Err.Error(), er.Status)
}

func WriteDbError(w http.ResponseWriter, request string, err error, errmsg string, er1 Err, er2 Err) {

	switch {

	case errors.Is(err, context.DeadlineExceeded):

		loggr.Error("request timeout error",
			"request", request,
			"message", errmsg,
			"error", err,
			"status", RequestTimeoutError.Status)
		http.Error(w, RequestTimeoutError.Err.Error(), RequestTimeoutError.Status)

	case errors.Is(err, sql.ErrNoRows):

		loggr.Error("no rows error",
			"request", request,
			"message", errmsg,
			"error", err,
			"status", er1.Status)
		http.Error(w, er1.Err.Error(), er1.Status)

	default:

		loggr.Error("request error",
			"request", request,
			"message", errmsg,
			"error", err,
			"status", er2.Status)
		http.Error(w, er2.Err.Error(), er2.Status)
	}
}
