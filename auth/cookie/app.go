package cookie

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type CookieAuth struct {
	DB                     *pgxpool.Pool
	QueryTimeout           time.Duration
	sessionTokenExpiration time.Duration
	refreshTokenExpiration time.Duration
}

func New(db *pgxpool.Pool, queryTimeout time.Duration, sessionExpiration time.Duration, refreshExpiration time.Duration) *CookieAuth {
	return &CookieAuth{
		DB:                     db,
		QueryTimeout:           queryTimeout,
		sessionTokenExpiration: sessionExpiration,
		refreshTokenExpiration: refreshExpiration,
	}
}
