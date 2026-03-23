package middlewares

import (
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

//
// Rate Limimter struct for a global mutex and a map of clients

type RateLimiter struct {
	mu      sync.RWMutex
	clients map[string]*client
	rps     int
	burst   int
}
