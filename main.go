package main

import (
	"apis/auth"
	"context"
	"log"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

////
////
////

// Data Table

/*

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    session_token TEXT,
    csrf_token TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

*/

////
////
////

//
// Database configuration

type App struct {
	DB *pgxpool.Pool
}

func main() {

	//
	// Loading the env file

	ctx := context.Background()

	err := godotenv.Load("dev.env")
	if err != nil {
		log.Fatalf("Error loading the .env file: %v", err)
	}

	//
	// Connecting to the database

	dbpool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}
	defer dbpool.Close()

	//
	// Database check

	err = dbpool.Ping(ctx)
	if err != nil {
		log.Fatalf("Database unreachable: %v\n", err)
	}
	log.Println("Database ok")

	//
	// Database instance initialization

	app := &App{DB: dbpool}
	authService := &auth.AuthService{DB: app.DB}

	//
	// Services

	http.HandleFunc("/register", authService.Register)

	http.HandleFunc("/login", authService.Login)

	http.HandleFunc("/protected", authService.Protected)

	http.HandleFunc("/logout", authService.Logout)

	http.HandleFunc("/delete", authService.DeleteAccount)

	//
	// Server start

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
