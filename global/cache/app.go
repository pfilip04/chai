package cache

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

type specialInfo struct {
	secret []byte
	issuer string
}

type Identity struct {
	UserID    uuid.UUID
	ExpiresAt time.Time
}

type Cache struct {
	j_info    *specialInfo
	mu        sync.RWMutex
	lookupMap map[string]Identity // identity -> userID + expiry(for cleanup)
}
