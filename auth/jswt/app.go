package jswt

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pfilip04/chai/config"
	"github.com/pfilip04/chai/mailing"
)

type JWTAuth struct {
	DB                     *pgxpool.Pool
	queryTimeout           time.Duration
	secret                 []byte
	issuer                 string
	jwtTokenExpiration     time.Duration
	refreshTokenExpiration time.Duration
	sender                 *mailing.Sender
	mailingExpiration      config.MailConfig
}

func New(db *pgxpool.Pool, queryTimeout time.Duration, secret []byte, specialname string, jExpiration time.Duration, rExpiration time.Duration, sendr *mailing.Sender, mailing config.MailConfig) *JWTAuth {
	return &JWTAuth{
		DB:                     db,
		queryTimeout:           queryTimeout,
		secret:                 secret,
		issuer:                 specialname,
		jwtTokenExpiration:     jExpiration,
		refreshTokenExpiration: rExpiration,
		sender:                 sendr,
		mailingExpiration:      mailing,
	}
}
