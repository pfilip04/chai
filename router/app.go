package router

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfilip04/chai/auth/code"
	"github.com/pfilip04/chai/auth/cookie"
	"github.com/pfilip04/chai/auth/jswt"
	"github.com/pfilip04/chai/config"
	"github.com/pfilip04/chai/mailing"
)

type App struct {
	DB     *pgxpool.Pool
	Cookie *cookie.CookieAuth
	JWT    *jswt.JWTAuth
	Code   *code.VerificationCode
}

func NewApp(dbpool *pgxpool.Pool) *App {

	return &App{
		DB: dbpool,
	}
}

func (a *App) InitCookie(cookiecfg config.CookieConfig, sender *mailing.Sender, mailCfg config.MailConfig) {
	a.Cookie = cookie.New(
		a.DB,
		time.Duration(cookiecfg.QueryTimeout),
		time.Duration(cookiecfg.SessionTokenExpiration),
		time.Duration(cookiecfg.RefreshTokenExpiration),
		sender,
		mailCfg,
	)
}

func (a *App) InitJWT(jwtcfg config.JWTConfig, sender *mailing.Sender, mailCfg config.MailConfig, secret string) {
	a.JWT = jswt.New(
		a.DB,
		time.Duration(jwtcfg.QueryTimeout),
		[]byte(secret),
		jwtcfg.SpecialName,
		time.Duration(jwtcfg.JwtTokenExpiration),
		time.Duration(jwtcfg.RefreshTokenExpiration),
		sender,
		mailCfg,
	)
}

func (a *App) InitCode(queryTimeout config.Duration) {
	a.Code = code.New(
		a.DB,
		time.Duration(queryTimeout),
	)
}
