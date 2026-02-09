package main

import (
	"log"
	"net/http"
	"time"

	"github.com/pfilip04/chai/router"
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

func main() {

	//
	//Significant variables

	envfile := "dev.env"
	timeout := 15 * time.Second
	cookieQtimeout := 3 * time.Second
	jwtQtimeout := 3 * time.Second
	var reqsize int64 = 1 << 20

	//
	// Router initialization

	r, dbpool, err := router.NewRouter(envfile, timeout, cookieQtimeout, jwtQtimeout, reqsize)
	if err != nil {
		log.Fatalf("Failed: %v", err)
	}
	defer dbpool.Close()

	//
	// Server start

	server := &http.Server{
		Addr:              ":8080",
		Handler:           r,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
