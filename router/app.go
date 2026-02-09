package router

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfilip04/chai/auth/cookie"
	"github.com/pfilip04/chai/auth/jswt"
)

type App struct {
	DB     *pgxpool.Pool
	Cookie *cookie.CookieAuth
	JWT    *jswt.JWTAuth
}

func NewApp(dbpool *pgxpool.Pool) *App {

	return &App{
		DB: dbpool,
		Cookie: &cookie.CookieAuth{
			DB: dbpool,
		},
		JWT: &jswt.JWTAuth{
			DB: dbpool,
		},
	}
}

func (a *App) InitJWT(queryTimeout time.Duration, secret []byte, specialname string, expiration time.Duration) {
	a.JWT = jswt.New(
		a.DB,
		queryTimeout,
		secret,
		specialname,
		expiration,
	)
}

func (a *App) InitCookie(queryTimeout time.Duration) {
	a.Cookie = cookie.New(
		a.DB,
		queryTimeout,
	)
}
