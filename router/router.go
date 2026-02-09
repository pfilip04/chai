package router

import (
	"log"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/jackc/pgx/v5/pgxpool"
)

func NewRouter(envfile string, timeout time.Duration, reqsize int64) (chi.Router, *pgxpool.Pool, error) {

	//
	// Load env

	if err := LoadEnv(envfile); err != nil {
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

	app := NewApp(dbpool)

	//
	// Router init

	router := app.NewChiRouter(timeout, reqsize)

	return router, dbpool, nil
}
