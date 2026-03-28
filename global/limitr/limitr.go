package limitr

import (
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pfilip04/chai/config"
	"github.com/pfilip04/chai/global/cache"
	"github.com/pfilip04/chai/global/errs"
	"golang.org/x/time/rate"
)

//
// Rate Limiter Constructor

func NewRateLimiter(rlcfg config.RateLimitConfig, db *pgxpool.Pool, secret []byte, issuer string) *RateLimiter {

	rl := &RateLimiter{
		db:              db,
		timeout:         time.Duration(rlcfg.QueryTimeout),
		ipClients:       make(map[string]*client),
		userClients:     make(map[string]*client),
		identifierCache: cache.NewCache(secret, issuer),
		ipRps:           rlcfg.IpRps,
		ipBurst:         rlcfg.IpBurst,
		userIdRps:       rlcfg.UserIdRps,
		userIdBurst:     rlcfg.UserIdBurst,
	}

	go rl.limiterCleanup(time.Duration(rlcfg.IpCacheLifetime), time.Duration(rlcfg.IdentifierCacheLifetime))

	return rl
}

func (rl *RateLimiter) InitRateLimiter() func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {

		fn := func(w http.ResponseWriter, r *http.Request) {

			// IP

			ip, _, err := net.SplitHostPort(r.RemoteAddr)

			if err != nil {

				errs.WriteError(w, "rate-limiter", err, "Problem when extracting ip", errs.ServerError)
				return
			}

			// Limiter limit and get client

			ipClient := rl.getLimiter(rl.ipClients, ip, rl.ipRps, rl.ipBurst)

			// Set last seen

			rl.mu.Lock()

			ipClient.lastSeenAt = time.Now().UTC()

			rl.mu.Unlock()

			// Check the limiter status

			if !ipClient.limiter.Allow() {

				errs.WriteError(w, "rate-limiter", errs.TooManyRequestsError.Err, "Too many requests", errs.TooManyRequestsError)
				return
			}

			// IDENTIFIER

			userID, miss, err := rl.identifierCache.GetCache(r.Context())

			if err != nil {

				errs.WriteError(w, "rate-limiter", err, "Problem when getting cache", errs.ServerError)
				return
			}

			if miss != "" {

				userID, err = rl.identifierCache.SetCache(r.Context(), rl.db, rl.timeout, miss)

				if err != nil {

					errs.WriteError(w, "rate-limiter", err, "Problem when setting cache", errs.ServerError)
					return
				}
			}

			// Skiping unidentified users for identifier limiting

			if userID == uuid.Nil {

				next.ServeHTTP(w, r)
				return
			}

			userIdStr := userID.String()

			// Limiter limit and get client

			userClient := rl.getLimiter(rl.userClients, userIdStr, rl.userIdRps, rl.userIdBurst)

			// Set last seen

			rl.mu.Lock()

			userClient.lastSeenAt = time.Now().UTC()

			rl.mu.Unlock()

			// Check the limiter status

			if !userClient.limiter.Allow() {

				errs.WriteError(w, "rate-limiter", errs.TooManyRequestsError.Err, "Too many requests (USER)", errs.TooManyRequestsError)
				return
			}

			// Call next (standard for middleware utility)

			next.ServeHTTP(w, r)
		}

		return http.HandlerFunc(fn)
	}
}

// Limiting in the map according to forwarded parameter

func (rl *RateLimiter) getLimiter(limiters map[string]*client, parameter string, rps int, burst int) *client {

	rl.mu.RLock()

	c, ok := limiters[parameter]

	rl.mu.RUnlock()

	if ok {

		return c
	}

	rl.mu.Lock()

	c, ok = limiters[parameter]

	if !ok {

		c = &client{
			limiter: rate.NewLimiter(rate.Limit(rps), burst),
		}

		limiters[parameter] = c
	}

	rl.mu.Unlock()

	return c
}
