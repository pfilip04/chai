package jswt

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/pfilip04/chai/utils"
)

func (j *JWTAuth) Login(w http.ResponseWriter, r *http.Request) {

	//
	// Username and password check

	username := r.FormValue("username")
	password := r.FormValue("password")

	var sessionID uuid.UUID
	var userID uuid.UUID
	var passwordHash string

	ctxA, cancelA := context.WithTimeout(r.Context(), j.QueryTimeout)
	defer cancelA()

	err := j.DB.QueryRow(ctxA,
		`SELECT id, password_hash FROM users 
		WHERE username=$1`,
		username,
	).Scan(&userID, &passwordHash)

	if err != nil || !utils.CheckPasswordHash(password, passwordHash) {

		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	ctxB, cancelB := context.WithTimeout(r.Context(), j.QueryTimeout)
	defer cancelB()

	expiresAt := time.Now().Add(30 * 24 * time.Hour)

	err = j.DB.QueryRow(ctxB,
		`INSERT INTO sessions (user_id, platform, expires_at) 
		VALUES ($1, $2, $3) 
		RETURNING id`,
		userID,
		"mobile",
		expiresAt,
	).Scan(&sessionID)

	if err != nil {

		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	tokenString, err := utils.CreateJWT(j.secret, userID, sessionID, j.specialname, j.expiration)

	if err != nil {

		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := utils.GenerateToken(64)

	if err != nil {

		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	hashedRefresh := utils.HashToken(refreshToken)

	ctxC, cancelC := context.WithTimeout(r.Context(), j.QueryTimeout)
	defer cancelC()

	_, err = j.DB.Exec(ctxC,
		`INSERT INTO refresh_tokens (session_id, token_hash, expires_at) 
		VALUES ($1, $2, $3)`,
		sessionID,
		hashedRefresh,
		expiresAt,
	)

	if err != nil {

		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Authorization", "Bearer "+tokenString)

	resp := struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}{
		Token:        tokenString,
		RefreshToken: refreshToken,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {

		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}
