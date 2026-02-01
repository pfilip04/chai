package main

import (
	"apis/cookie_auth"
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

////
////

// Data Table

/*

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
	email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    session_token TEXT,
    csrf_token TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

*/

////
////

//
// Database configuration

type App struct {
	DB *pgxpool.Pool
}

func main() {

	ctx := context.Background()

	//
	// Loading the env file

	err := godotenv.Load("dev.env")
	if err != nil {
		log.Fatalf("Error loading the .env file: %v", err)
	}

	//
	// Connecting to the database

	ctx30, cancel30 := context.WithTimeout(ctx, 30*time.Second)
	defer cancel30()

	dbpool, err := pgxpool.New(ctx30, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}
	defer dbpool.Close()

	//
	// Database check

	ctx5, cancel5 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel5()

	err = dbpool.Ping(ctx5)
	if err != nil {
		log.Fatalf("Database unreachable: %v\n", err)
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

	//
	// Server start

	server := &http.Server{
		Addr:              ":8080",
		Handler:           router,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
