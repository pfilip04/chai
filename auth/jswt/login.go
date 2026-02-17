package jswt

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/pfilip04/chai/errs"
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

	if err != nil {

		http.Error(w, "Invalid username", http.StatusUnauthorized)
		return
	}

	if !utils.CheckPasswordHash(password, passwordHash) {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	refreshExpiresAt := time.Now().UTC().Add(j.refreshTokenExpiration)

	ctxB, cancelB := context.WithTimeout(r.Context(), j.QueryTimeout)
	defer cancelB()

	err = j.DB.QueryRow(ctxB,
		`INSERT INTO sessions (user_id, platform, expires_at) 
		VALUES ($1, $2, $3) 
		RETURNING id`,
		userID,
		"mobile",
		refreshExpiresAt,
	).Scan(&sessionID)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	tokenString, err := utils.CreateJWT(j.secret, userID, sessionID, j.issuer, j.jwtTokenExpiration)

	if err != nil {

		http.Error(w, "Couldn't create JWT", http.StatusInternalServerError)
		return
	}

	refreshToken, err := utils.GenerateToken(64)

	if err != nil {

		http.Error(w, "Couldn't generate refresh token", http.StatusInternalServerError)
		return
	}

	hashedRefresh := utils.HashToken(refreshToken)

	ctxC, cancelC := context.WithTimeout(r.Context(), j.QueryTimeout)
	defer cancelC()

	_, err = j.DB.Exec(ctxC,
		`INSERT INTO refresh_tokens (session_id, refresh_token, expires_at) 
		VALUES ($1, $2, $3)`,
		sessionID,
		hashedRefresh,
		refreshExpiresAt,
	)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Authorization", "Bearer "+tokenString)
	w.WriteHeader(http.StatusOK)

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
