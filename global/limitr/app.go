package limitr

import (
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
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
	db      *pgxpool.Pool
	timeout time.Duration

	mu sync.RWMutex

	ipClients   map[string]*client
	userClients map[string]*client

	identifierCache *cache.Cache

	ipRps   int
	ipBurst int

	userIdRps   int
	userIdBurst int
}
