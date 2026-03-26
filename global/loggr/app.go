package loggr

import "net/http"

//
// A wrapper around the Response writer to capture the status code for logging

type responseWriter struct {
	http.ResponseWriter
	status int
}
