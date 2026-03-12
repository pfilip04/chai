package jswt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/mailing"
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

	user, err := repo.GetUserByIdOrUsername(ctxA, repository.GetUserByIdOrUsernameParams{
		Username: username,
		ID:       uuid.Nil,
	})

	if err != nil || !utils.CheckPasswordHash(password, user.PasswordHash) {

		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	if j.sender != nil {

		if !user.EmailVerified {

			http.Error(w, errs.AuthError.Err.Error(), http.StatusUnauthorized)
			return
		}

		if user.Mfa {

			message, err := mailing.SendMail(mailing.DbQuerying{
				Repo:         repo,
				QueryTimeout: j.queryTimeout,
				Ctx:          r.Context(),
			}, mailing.Mailc{
				MExp:    j.mailingExpiration.MfaLoginExpiry,
				MailCfg: j.mailingExpiration,
			}, mailing.User{
				UserID:    user.ID,
				Username:  username,
				UserEmail: user.Email,
			}, mailing.MfaType{
				ApiName:  enums.MfaLoginVerify,
				MailName: enums.Login,
			}, j.sender)

			if err != nil {

				http.Error(w, errs.ServerError.Err.Error(), errs.ServerError.Status)
				return
			}

			fmt.Fprintln(w, message)
			return
		}
	}

	refreshToken, err := utils.GenerateToken(64)

	if err != nil {

		http.Error(w, "Couldn't generate refresh token", http.StatusInternalServerError)
		return
	}

	hashedRefresh := utils.HashToken(refreshToken)

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
