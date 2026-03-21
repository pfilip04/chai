package jswt

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
)

func (j *JWTAuth) Refresh(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the Refresh Authorization Token

	userID, sessionID, hashedRefreshToken, err := j.AuthorizeRefresh(r)

	if err != nil {

		errs.WriteError(w, enums.Refresh, err, "JWT: Problem when Authorizing action", errs.AuthError)
		return
	}

	//
	// Generating the JWT and Refresh Token, Hashing the Refresh Token

	tokenString, err := utils.CreateJWT(j.secret, userID, sessionID, j.issuer, j.jwtTokenExpiration)

	if err != nil {

		errs.WriteError(w, enums.Refresh, err, "JWT: Couldn't generate JWT", errs.ServerError)
		return
	}

	newRefreshToken, err := utils.GenerateToken(64)

	if err != nil {

		errs.WriteError(w, enums.Refresh, err, "JWT: Couldn't generate refresh token", errs.ServerError)
		return
	}

	hashedNewRefresh := utils.HashToken(newRefreshToken)

	//
	// Expiry time

	refreshExpiresAt := time.Now().UTC().Add(j.refreshTokenExpiration)

	ctxC, cancelC := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelC()

	tx, err := j.DB.Begin(ctxC)

	if err != nil {

		errs.WriteError(w, enums.Refresh, err, "JWT: Transaction start error", errs.ServerError)
		return
	}

	defer tx.Rollback(ctxC)

	repo := repository.New(tx)

	//
	// Updating the Session into the DB

	rows, err := repo.UpdateJWTSession(ctxC, repository.UpdateJWTSessionParams{
		ExpiresAt: refreshExpiresAt,
		ID:        sessionID,
	})

	if err != nil {

		errs.WriteError(w, enums.Refresh, err, "JWT: Couldn't update the session in the db", errs.AuthError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.Refresh, errs.DatabaseError.Err, "JWT: No session is updated", errs.DatabaseError)
		return
	}

	rows, err = repo.UpdateRefreshToken(ctxC, repository.UpdateRefreshTokenParams{
		RefreshToken:   hashedNewRefresh,
		ExpiresAt:      refreshExpiresAt,
		RefreshToken_2: hashedRefreshToken,
		SessionID:      sessionID,
	})

	if err != nil {

		errs.WriteError(w, enums.Refresh, err, "JWT: Couldn't update the refresh in the db", errs.AuthError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.Refresh, errs.DatabaseError.Err, "JWT: No refresh is updated", errs.DatabaseError)
		return
	}

	if err := tx.Commit(ctxC); err != nil {

		errs.WriteError(w, enums.Refresh, err, "JWT: Transaction commit error", errs.DatabaseError)
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

		errs.WriteError(w, enums.Refresh, err, "JWT: Failed to encode response", errs.ServerError)
		return
	}
}
