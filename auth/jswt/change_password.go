package jswt

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/mailing"
	"github.com/pfilip04/chai/utils"
)

func (j *JWTAuth) ChangePassword(w http.ResponseWriter, r *http.Request) {

	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {

		http.Error(w, errs.AuthError.Error(), http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	userID, _, err := utils.CheckJWT(token, j.secret, j.issuer)

	if err != nil {

		http.Error(w, errs.AuthError.Error(), http.StatusUnauthorized)
		return
	}

	password := r.FormValue("old-password")

	ctxA, cancelA := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelA()

	repo := repository.New(j.DB)

	user, err := repo.GetUsernameEmailPasswordMfaById(ctxA, userID)

	if err != nil || !utils.CheckPasswordHash(password, user.PasswordHash) {

		http.Error(w, errs.AuthError.Error(), http.StatusUnauthorized)
		return
	}

	if j.sender != nil && user.Mfa {

		code, err := utils.GenerateOTP(10, 6)

		if err != nil {

			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		codeHash := utils.HashToken(code)

		codeExpiresAt := time.Now().UTC().Add(time.Duration(j.mailingExpiration.ChangePassExpiry))

		ctxB, cancelB := context.WithTimeout(r.Context(), j.queryTimeout)
		defer cancelB()

		mfaId, err := repo.CreateMfaMail(ctxB, repository.CreateMfaMailParams{
			UserID:    userID,
			MfaType:   enums.MfaChangePassword,
			Code:      codeHash,
			ExpiresAt: codeExpiresAt,
		})

		if err != nil {

			http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
			return
		}

		ctxC, cancelC := context.WithTimeout(r.Context(), j.queryTimeout)
		defer cancelC()

		err = mailing.Mail(ctxC, j.mailingExpiration, *j.sender, mailing.Verification{
			Id:      mfaId,
			ApiName: enums.MfaChangePassword,
			Code:    code,
		}, mailing.User{
			Username:  user.Username,
			UserEmail: user.Email,
		})

		if err != nil {

			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		fmt.Fprintln(w, "Password change mail sent successfully!")
	}
}
