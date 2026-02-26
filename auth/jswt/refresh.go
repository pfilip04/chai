package jswt

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
)

func (j *JWTAuth) Refresh(w http.ResponseWriter, r *http.Request) {

	rf := r.Header.Get("REFRESH-TOKEN")
	if rf == "" {

		http.Error(w, errs.AuthError.Error(), http.StatusUnauthorized)
		return
	}

	hashedRefreshToken := utils.HashToken(rf)

	refreshExpiresAt := time.Now().UTC().Add(j.refreshTokenExpiration)

	ctxA, cancelA := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelA()

	repo := repository.New(j.DB)

	sessionID, err := repo.GetSessionIdByRefresh(ctxA, hashedRefreshToken)

	if err != nil {

		http.Error(w, "Couldn't find refresh", http.StatusUnauthorized)
		return
	}

	ctxB, cancelB := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelB()

	userID, err := repo.GetUserIdBySessionId(ctxB, sessionID)

	if err != nil {

		http.Error(w, "Couldn't find userID", http.StatusUnauthorized)
		return
	}

	tokenString, err := utils.CreateJWT(j.secret, userID, sessionID, j.issuer, j.jwtTokenExpiration)

	if err != nil {

		http.Error(w, "Couldn't generate JWT", http.StatusInternalServerError)
		return
	}

	newRefreshToken, err := utils.GenerateToken(64)

	if err != nil {

		http.Error(w, "Couldn't generate refresh token", http.StatusInternalServerError)
		return
	}

	hashedNewRefresh := utils.HashToken(newRefreshToken)

	ctxC, cancelC := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelC()

	tx, err := j.DB.Begin(ctxC)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	defer tx.Rollback(ctxC)

	repo = repository.New(tx)

	rows, err := repo.UpdateJWTSession(ctxC, repository.UpdateJWTSessionParams{
		ExpiresAt: refreshExpiresAt,
		ID:        sessionID,
	})

	if err != nil {

		http.Error(w, "Couldn't refresh tokens", http.StatusUnauthorized)
		return
	}

	if rows == 0 {
		http.Error(w, "Couldn't find session", http.StatusUnauthorized)
		return
	}

	rows, err = repo.UpdateRefreshToken(ctxC, repository.UpdateRefreshTokenParams{
		RefreshToken:   hashedNewRefresh,
		ExpiresAt:      refreshExpiresAt,
		RefreshToken_2: hashedRefreshToken,
		SessionID:      sessionID,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	if rows == 0 {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	if err := tx.Commit(ctxC); err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
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
