package router

import (
	"errors"
	"log"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfilip04/chai/config"
)

func NewRouter() (chi.Router, *pgxpool.Pool, error) {

	//
	// Load the config

	cfg, err := config.Load("config/config.json")
	if err != nil {
		return nil, nil, err
	}

	//
	// Load env

	if err := LoadEnv(cfg.Env); err != nil {
		return nil, nil, err
	}

	//
	// Connect to DB

	dbpool, err := ConnectDB("DATABASE_URL")
	if err != nil {
		return nil, nil, err
	} else {
		log.Println("Database ok")
	}

	//
	// App init

	secret := os.Getenv("SECRET_KEY")
	if secret == "" {
		return nil, nil, errors.New("SECRET_KEY IS NOT SET")
	}

	app := NewApp(dbpool)

	app.InitCookie(cfg.Cookie)

	app.InitJWT(cfg.JWT, secret)

	//
	// Router init

	router := app.NewChiRouter(cfg.Router)

	return router, dbpool, nil
}
