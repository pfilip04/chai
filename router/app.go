package router

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfilip04/chai/auth/cookie"
	"github.com/pfilip04/chai/auth/jswt"
	"github.com/pfilip04/chai/config"
)

type App struct {
	DB     *pgxpool.Pool
	Cookie *cookie.CookieAuth
	JWT    *jswt.JWTAuth
}

func NewApp(dbpool *pgxpool.Pool) *App {

	return &App{
		DB: dbpool,
	}
}

func (a *App) InitCookie(cookiecfg config.CookieConfig) {
	a.Cookie = cookie.New(
		a.DB,
		time.Duration(cookiecfg.QueryTimeout),
	)
}

func (a *App) InitJWT(jwtcfg config.JWTConfig, secret string) {
	a.JWT = jswt.New(
		a.DB,
		time.Duration(jwtcfg.QueryTimeout),
		[]byte(secret),
		jwtcfg.SpecialName,
		time.Duration(jwtcfg.Expiration),
	)
}
