package middlewares

import (
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

//
// A wrapper around the Response writer to capture the status code for logging

type responseWriter struct {
	http.ResponseWriter
	status int
}

//
// Overridding the WriteHeader func so it sets the code for logging before it writes

func (rw *responseWriter) WriteHeader(code int) {

	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

//
// Logger configurations

func SlogMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			start := time.Now()
			ww := &responseWriter{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(ww, r)

			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			reqID := middleware.GetReqID(r.Context())

			logger.Info("http_request",
				"req_id", reqID,
				"method", r.Method,
				"path", r.URL.Path,
				"ip", ip,
				"status", ww.status,
				"duration", time.Since(start),
			)
		})
	}
}

//
// New Logger instance func

func NewLogger() *slog.Logger {

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	return slog.New(handler)
}
