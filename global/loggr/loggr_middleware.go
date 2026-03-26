package loggr

import (
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

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
