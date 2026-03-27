package limitr

import (
	"sync"
	"time"

	"github.com/pfilip04/chai/global/cache"
	"golang.org/x/time/rate"
)

//
// Client struct for tracking requests and last-seen for cleanup

type client struct {
	limiter    *rate.Limiter
	lastSeenAt time.Time
}

//
// Rate Limimter struct for a global mutex and a map of clients

type RateLimiter struct {
	mu              sync.RWMutex
	identifierCache *cache.Cache
	clients         map[string]*client
	rps             int
	burst           int
}
