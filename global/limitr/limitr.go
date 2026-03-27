package limitr

import (
	"net"
	"net/http"
	"time"

	"github.com/pfilip04/chai/global/cache"
	"github.com/pfilip04/chai/global/errs"
	"golang.org/x/time/rate"
)

//
// Rate Limiter Constructor

func NewRateLimiter(rps int, burst int, lifetime time.Duration, secret []byte, issuer string) *RateLimiter {

	rl := &RateLimiter{
		clients:         make(map[string]*client),
		identifierCache: cache.NewCache(secret, issuer),
		rps:             rps,
		burst:           burst,
	}

	go rl.limiterCleanup(lifetime)

	return rl
}

func (rl *RateLimiter) InitRateLimiter() func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {

		fn := func(w http.ResponseWriter, r *http.Request) {

			// IP

			ip, _, err := net.SplitHostPort(r.RemoteAddr)

			if err != nil {

				errs.WriteError(w, "rate limiter", err, "Problem when extracting ip", errs.ServerError)
				return
			}

			rl.mu.RLock()
			c, ok := rl.clients[ip]
			rl.mu.RUnlock()

			if !ok {

				rl.mu.Lock()
				c, ok = rl.clients[ip]
				if !ok {

					c = &client{
						limiter: rate.NewLimiter(rate.Limit(rl.rps), rl.burst),
					}
					rl.clients[ip] = c
				}
				rl.mu.Unlock()
			}

			rl.mu.Lock()
			c.lastSeenAt = time.Now().UTC()
			rl.mu.Unlock()

			// Check the limiter status

			if !c.limiter.Allow() {

				errs.WriteError(w, "rate limiter", errs.TooManyRequestsError.Err, "Too many requests", errs.TooManyRequestsError)
				return
			}

			// Call next (standard for middleware utility)

			next.ServeHTTP(w, r)
		}

		return http.HandlerFunc(fn)
	}
}
