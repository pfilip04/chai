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
	// Extracting Form Values

	usernameOrEmail := r.FormValue("username_or_email")
	password := r.FormValue("password")

	ctxA, cancelA := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelA()

	repo := repository.New(j.DB)

	//
	// Username and password check

	user, err := repo.GetUserByUsernameOrEmail(ctxA, usernameOrEmail)

	if err != nil {

		http.Error(w, "Invalid username", http.StatusConflict)
		return
	}

	if !utils.CheckPasswordHash(password, user.PasswordHash) {

		http.Error(w, "Incorrect password", http.StatusConflict)
		return
	}

	//
	// If Mailing was specified in the JSON check if the Email is Verified, no MFA Login for mobile (JWT)

	if j.sender != nil {

		if !user.EmailVerified {

			http.Error(w, errs.AuthError.Err.Error(), http.StatusUnauthorized)
			return
		}
	}

	//
	// Generating and Hashing Refresh Token

	refreshToken, err := utils.GenerateToken(64)

	if err != nil {

		http.Error(w, "Couldn't generate refresh token", http.StatusInternalServerError)
		return
	}

	hashedRefresh := utils.HashToken(refreshToken)

	//
	// Expiry time

	refreshExpiresAt := time.Now().UTC().Add(j.refreshTokenExpiration)

	ctxE, cancelE := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelE()

	tx, err := j.DB.Begin(ctxE)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	defer tx.Rollback(ctxE)

	repo = repository.New(tx)

	//
	// Inserting the Session into the DB

	sessionID, err := repo.InsertJWTSession(ctxE, repository.InsertJWTSessionParams{
		UserID:    user.ID,
		Platform:  "mobile",
		ExpiresAt: refreshExpiresAt,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	tokenString, err := utils.CreateJWT(j.secret, user.ID, sessionID, j.issuer, j.jwtTokenExpiration)

	if err != nil {

		http.Error(w, "Couldn't create JWT", http.StatusInternalServerError)
		return
	}

	err = repo.InsertRefreshToken(ctxE, repository.InsertRefreshTokenParams{
		SessionID:    sessionID,
		RefreshToken: hashedRefresh,
		ExpiresAt:    refreshExpiresAt,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(ctxE); err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	//
	// Setting the JWT Token in the Header

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
