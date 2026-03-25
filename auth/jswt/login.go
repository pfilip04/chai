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

		errs.WriteError(w, enums.Login, err, "JWT: Incorrect username or email", errs.AuthError)
		return
	}

	if !utils.CheckPasswordHash(password, user.PasswordHash) {

		errs.WriteError(w, enums.Login, errs.AuthError.Err, "JWT: Incorrect password", errs.AuthError)
		return
	}

	if err = utils.IsValidStatus(r, user.ID, user.Status, user.SuspendedAt, user.SuspendedFor, user.DeletedAt, j.DB, j.queryTimeout); err != nil {

		errs.WriteError(w, enums.Login, err, "Cookie: Problem validating status", errs.ForbiddenError)
		return
	}

	//
	// If Mailing was specified in the JSON check if the Email is Verified, no MFA Login for mobile (JWT)

	if j.sender != nil {

		if !user.EmailVerified {

			errs.WriteError(w, enums.Login, errs.AuthError.Err, "JWT: Email not verified", errs.AuthError)
			return
		}
	}

	//
	// Generating and Hashing Refresh Token

	refreshToken, err := utils.GenerateToken(64)

	if err != nil {

		errs.WriteError(w, enums.Login, err, "JWT: Couldn't generate refresh token", errs.ServerError)
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

		errs.WriteError(w, enums.Login, err, "JWT: Transaction start error", errs.ServerError)
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

		errs.WriteError(w, enums.Login, err, "JWT: Couldn't insert session into the db", errs.DatabaseError)
		return
	}

	tokenString, err := utils.CreateJWT(j.secret, user.ID, sessionID, j.issuer, j.jwtTokenExpiration)

	if err != nil {

		errs.WriteError(w, enums.Login, err, "JWT: Couldn't create JWT", errs.ServerError)
		return
	}

	err = repo.InsertRefreshToken(ctxE, repository.InsertRefreshTokenParams{
		SessionID:    sessionID,
		RefreshToken: hashedRefresh,
		ExpiresAt:    refreshExpiresAt,
	})

	if err != nil {

		errs.WriteError(w, enums.Login, err, "JWT: Couldn't insert refresh token into the db", errs.DatabaseError)
		return
	}

	if err := tx.Commit(ctxE); err != nil {

		errs.WriteError(w, enums.Login, err, "JWT: Transaction commit error", errs.DatabaseError)
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

		errs.WriteError(w, enums.Login, err, "JWT: Failed to encode response", errs.ServerError)
		return
	}
}
