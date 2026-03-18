package router

import (
	"net"
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

	var mu sync.RWMutex
	var clients = make(map[string]*client)

	return func(next http.Handler) http.Handler {

		fn := func(w http.ResponseWriter, r *http.Request) {

			// IP

			ip, _, err := net.SplitHostPort(r.RemoteAddr)

			if err != nil {

				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			mu.RLock()
			c, ok := clients[ip]
			mu.RUnlock()

			if !ok {

				mu.Lock()
				c, ok = clients[ip]
				if !ok {

					c = &client{
						limiter: rate.NewLimiter(rate.Limit(rps), burst),
					}
					clients[ip] = c
				}
				mu.Unlock()
			}

			mu.Lock()
			c.lastSeenAt = time.Now().UTC()
			mu.Unlock()

			// Check the limiter status

			if !c.limiter.Allow() {

				http.Error(w, "Too many requests!", http.StatusTooManyRequests)
				return
			}

			// Call next (standard for middleware utility)

			next.ServeHTTP(w, r)
		}

		return http.HandlerFunc(fn)
	}
}
