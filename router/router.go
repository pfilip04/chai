package router

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"

	"github.com/pfilip04/chai/cookie_auth"
)

type App struct {
	DB *pgxpool.Pool
}

func NewRouter(envfile string) (chi.Router, *pgxpool.Pool, error) {

	ctx := context.Background()

	//
	// Loading the env file

	err := godotenv.Load(envfile)
	if err != nil {
		return nil, nil, fmt.Errorf("Error loading the .env file: %v", err)
	}

	//
	// Connecting to the database

	ctx30, cancel30 := context.WithTimeout(ctx, 30*time.Second)
	defer cancel30()

	dbpool, err := pgxpool.New(ctx30, os.Getenv("DATABASE_URL"))
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to connect to database: %v\n", err)
	}

	//
	// Database check

	ctx5, cancel5 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel5()

	err = dbpool.Ping(ctx5)
	if err != nil {
		dbpool.Close()
		return nil, nil, fmt.Errorf("Database unreachable: %v\n", err)
	}
	log.Println("Database ok")

	//
	// Database instance initialization

	app := &App{DB: dbpool}
	cookieAuthService := &cookie_auth.AuthService{DB: app.DB}

	//
	// Services

	router := chi.NewRouter()

	// A good base middleware stack

	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	// Set a timeout value on the request context (ctx), that will signal
	// through ctx.Done() that the request has timed out and further
	// processing should be stopped.

	router.Use(middleware.Timeout(15 * time.Second))

	router.Use(middleware.RequestSize(1 << 20))

	// Api URLs

	router.Route("/auth", func(r chi.Router) {
		r.Post("/register", cookieAuthService.Register)
		r.Post("/login", cookieAuthService.Login)
		r.Post("/logout", cookieAuthService.Logout)
		r.Delete("/delete", cookieAuthService.DeleteAccount)
	})

	router.Get("/protected", cookieAuthService.ViewProtected)

	return router, dbpool, nil
}
