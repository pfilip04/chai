package jswt

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type JWTAuth struct {
	DB                     *pgxpool.Pool
	QueryTimeout           time.Duration
	secret                 []byte
	issuer                 string
	jwtTokenExpiration     time.Duration
	refreshTokenExpiration time.Duration
}

func New(db *pgxpool.Pool, queryTimeout time.Duration, secret []byte, specialname string, jExpiration time.Duration, rExpiration time.Duration) *JWTAuth {
	return &JWTAuth{
		DB:                     db,
		QueryTimeout:           queryTimeout,
		secret:                 secret,
		issuer:                 specialname,
		jwtTokenExpiration:     jExpiration,
		refreshTokenExpiration: rExpiration,
	}
}
