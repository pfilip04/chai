package errs

import (
	"context"
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
