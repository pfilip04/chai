package router

import (
	"errors"
	"log"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfilip04/chai/config"
)

func NewRouter(configurations string) (chi.Router, *pgxpool.Pool, error) {

	//
	// Load the config

	cfg, err := config.Load[config.Config](configurations)

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

	hcfg, err := config.Load[config.HandlerConfig](cfg.HandlerCfg)

	app := NewApp(dbpool)

	app.InitCookie(hcfg.Cookie)

	app.InitJWT(hcfg.JWT, secret)

	//
	// Router init

	router := app.NewChiRouter(hcfg.Router)

	return router, dbpool, nil
}
