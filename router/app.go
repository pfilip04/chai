package router

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfilip04/chai/cookie_auth"
)

type App struct {
	DB       *pgxpool.Pool
	CookieDB *cookie_auth.AuthService
}

func NewApp(dbpool *pgxpool.Pool) *App {

	return &App{
		DB: dbpool,
		CookieDB: &cookie_auth.AuthService{
			DB: dbpool,
		},
	}
}
