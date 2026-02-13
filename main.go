package main

import (
	"log"
	"net/http"
	"time"

	"github.com/pfilip04/chai/router"
)

////
////

// Database Schema

/*

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username	    TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    email_verified  BOOLEAN NOT NULL DEFAULT FALSE,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    session_token   TEXT UNIQUE,
    csrf_token      TEXT,

    platform        TEXT NOT NULL,
    user_agent      TEXT,
    device_name     TEXT,

    ip_address      INET,

    expires_at      TIMESTAMPTZ NOT NULL,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID REFERENCES sessions(id) ON DELETE CASCADE,

    refresh_token   TEXT NOT NULL UNIQUE,
    expires_at      TIMESTAMPTZ NOT NULL,

    replaced_by     UUID REFERENCES refresh_tokens(id) ON DELETE SET NULL,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_refresh_session_id ON refresh_tokens(session_id);

*/

////
////

func main() {

	//
	// Router initialization

	config := "config.json"

	r, dbpool, err := router.NewRouter(config)
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
