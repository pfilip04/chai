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

func (j *JWTAuth) Refresh(w http.ResponseWriter, r *http.Request) {

	rf := r.Header.Get("REFRESH-TOKEN")
	if rf == "" {

		http.Error(w, errs.AuthError.Error(), http.StatusUnauthorized)
		return
	}

	hashedRefreshToken := utils.HashToken(rf)

	var sessionID uuid.UUID
	var userID uuid.UUID

	refreshExpiresAt := time.Now().UTC().Add(j.refreshTokenExpiration)

	ctxA, cancelA := context.WithTimeout(r.Context(), j.QueryTimeout)
	defer cancelA()

	err := j.DB.QueryRow(ctxA,
		`SELECT session_id FROM refresh_tokens 
		WHERE refresh_token=$1 AND expires_at > NOW()`,
		hashedRefreshToken,
	).Scan(&sessionID)

	if err != nil {

		http.Error(w, "Couldn't find refresh", http.StatusUnauthorized)
		return
	}

	ctxB, cancelB := context.WithTimeout(r.Context(), j.QueryTimeout)
	defer cancelB()

	err = j.DB.QueryRow(ctxB,
		`SELECT user_id FROM sessions 
		WHERE id=$1 AND expires_at > NOW()`,
		sessionID,
	).Scan(&userID)

	if err != nil {

		http.Error(w, "Couldn't find userID", http.StatusUnauthorized)
		return
	}

	tokenString, err := utils.CreateJWT(j.secret, userID, sessionID, j.issuer, j.jwtTokenExpiration)

	if err != nil {

		http.Error(w, "Couldn't generate JWT", http.StatusInternalServerError)
		return
	}

	ctxC, cancelC := context.WithTimeout(r.Context(), j.QueryTimeout)
	defer cancelC()

	_, err = j.DB.Exec(ctxC,
		`UPDATE sessions 
		SET expires_at=$1 
		WHERE id=$2`,
		refreshExpiresAt,
		sessionID,
	)

	if err != nil {

		http.Error(w, "Couldn't refresh tokens", http.StatusUnauthorized)
		return
	}

	newRefreshToken, err := utils.GenerateToken(64)

	if err != nil {

		http.Error(w, "Couldn't generate refresh token", http.StatusInternalServerError)
		return
	}

	hashedNewRefresh := utils.HashToken(newRefreshToken)

	ctxD, cancelD := context.WithTimeout(r.Context(), j.QueryTimeout)
	defer cancelD()

	result, err := j.DB.Exec(ctxD,
		`UPDATE refresh_tokens 
		SET refresh_token=$1, expires_at=$2 
		WHERE refresh_token=$3 AND session_id=$4 AND expires_at > NOW()`,
		hashedNewRefresh,
		refreshExpiresAt,
		hashedRefreshToken,
		sessionID,
	)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	rows := result.RowsAffected()

	if rows == 0 {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Authorization", "Bearer "+tokenString)

	resp := struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}{
		Token:        tokenString,
		RefreshToken: newRefreshToken,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {

		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}
