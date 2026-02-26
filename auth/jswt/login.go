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

func (j *JWTAuth) Login(w http.ResponseWriter, r *http.Request) {

	//
	// Username and password check

	username := r.FormValue("username")
	password := r.FormValue("password")

	ctxA, cancelA := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelA()

	repo := repository.New(j.DB)

	User, err := repo.GetIdAndPass(ctxA, username)

	if err != nil || !utils.CheckPasswordHash(password, User.PasswordHash) {

		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	refreshToken, err := utils.GenerateToken(64)

	if err != nil {

		http.Error(w, "Couldn't generate refresh token", http.StatusInternalServerError)
		return
	}

	hashedRefresh := utils.HashToken(refreshToken)

	refreshExpiresAt := time.Now().UTC().Add(j.refreshTokenExpiration)

	ctxB, cancelB := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelB()

	tx, err := j.DB.Begin(ctxB)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	defer tx.Rollback(ctxB)

	repo = repository.New(tx)

	sessionID, err := repo.InsertJWTSession(ctxB, repository.InsertJWTSessionParams{
		UserID:    User.ID,
		Platform:  "mobile",
		ExpiresAt: refreshExpiresAt,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	tokenString, err := utils.CreateJWT(j.secret, User.ID, sessionID, j.issuer, j.jwtTokenExpiration)

	if err != nil {

		http.Error(w, "Couldn't create JWT", http.StatusInternalServerError)
		return
	}

	err = repo.InsertRefreshToken(ctxB, repository.InsertRefreshTokenParams{
		SessionID:    sessionID,
		RefreshToken: hashedRefresh,
		ExpiresAt:    refreshExpiresAt,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(ctxB); err != nil {

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
