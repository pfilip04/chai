package router

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

//
// Client struct for tracking requests and last-seen for cleanup

type client struct {
	limiter    *rate.Limiter
	lastSeenAt time.Time
}

func NewRateLimiter(rps int, burst int) func(http.Handler) http.Handler {

	// Mutex for safe access and the map of client structs

	var mu sync.Mutex
	var clients = make(map[string]*client)

	return func(next http.Handler) http.Handler {

		fn := func(w http.ResponseWriter, r *http.Request) {

			// IP

			ip := r.RemoteAddr

			// LOCK

			mu.Lock()

			// If new add to map

			if _, ok := clients[ip]; !ok {

				clients[ip] = &client{
					limiter: rate.NewLimiter(rate.Limit(rps), burst),
				}
			}

			// Update last-seen

			clients[ip].lastSeenAt = time.Now().UTC()

			limiter := clients[ip].limiter

			mu.Unlock()

			//UNLOCK

			// Check the limiter status

			if !limiter.Allow() {

				http.Error(w, "Too many requests!", http.StatusTooManyRequests)
				return
			}

			// Call next (standard for middleware utility)

			next.ServeHTTP(w, r)
		}

		return http.HandlerFunc(fn)
	}
}
