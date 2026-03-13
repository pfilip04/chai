package cookie

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pfilip04/chai/config"
	"github.com/pfilip04/chai/mailing"
)

type CookieAuth struct {
	DB                     *pgxpool.Pool
	queryTimeout           time.Duration
	sessionTokenExpiration time.Duration
	mfaTokenExpiration     time.Duration
	refreshTokenExpiration time.Duration
	sender                 *mailing.Sender
	mailingExpiration      config.MailConfig
}

func New(db *pgxpool.Pool, queryTimeout time.Duration, sessionExpiration time.Duration, mfaExpiration time.Duration, refreshExpiration time.Duration, sendr *mailing.Sender, mailing config.MailConfig) *CookieAuth {
	return &CookieAuth{
		DB:                     db,
		queryTimeout:           queryTimeout,
		sessionTokenExpiration: sessionExpiration,
		mfaTokenExpiration:     mfaExpiration,
		refreshTokenExpiration: refreshExpiration,
		sender:                 sendr,
		mailingExpiration:      mailing,
	}
}
