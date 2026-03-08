package jswt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

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

	user, err := repo.GetIdPasswordEmailVerifiedMfa(ctxA, username)

	if err != nil || !utils.CheckPasswordHash(password, user.PasswordHash) {

		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	if j.sender != nil {

		if !user.EmailVerified {

			http.Error(w, errs.AuthError.Error(), http.StatusUnauthorized)
			return
		}

		if user.Mfa {

			code, err := utils.GenerateOTP(10, 6)

			if err != nil {

				http.Error(w, "Server Error", http.StatusInternalServerError)
				return
			}

			codeHash := utils.HashToken(code)

			codeExpiresAt := time.Now().UTC().Add(time.Duration(j.mailingExpiration.MfaLoginExpiry))

			ctxB, cancelB := context.WithTimeout(r.Context(), j.queryTimeout)
			defer cancelB()

			user, err := repo.FindUserByUsernameOrEmail(ctxB, username)

			if err != nil {

				http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
				return
			}

			ctxC, cancelC := context.WithTimeout(r.Context(), j.queryTimeout)
			defer cancelC()

			mfaId, err := repo.CreateMfaMail(ctxC, repository.CreateMfaMailParams{
				UserID:    user.ID,
				MfaType:   enums.MfaLoginVerify,
				Code:      codeHash,
				ExpiresAt: codeExpiresAt,
			})

			if err != nil {

				http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
				return
			}

			ctxD, cancelD := context.WithTimeout(r.Context(), j.queryTimeout)
			defer cancelD()

			err = mailing.Mail(ctxD, j.mailingExpiration, *j.sender, mailing.Verification{
				Id:      mfaId,
				ApiName: enums.MfaLoginVerify,
				Code:    code,
			}, mailing.User{
				Username:  username,
				UserEmail: user.Email,
			})

			if err != nil {

				http.Error(w, "Server Error", http.StatusInternalServerError)
				return
			}

			fmt.Println(w, "Login mail succesfully sent")
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

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
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

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
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

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(ctxE); err != nil {

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
