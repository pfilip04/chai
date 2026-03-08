package jswt

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/mailing"
	"github.com/pfilip04/chai/utils"
)

func (j *JWTAuth) ForgotPassword(w http.ResponseWriter, r *http.Request) {

	usernameOrEmail := r.FormValue("username_or_email")

	ctxA, cancelA := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelA()

	repo := repository.New(j.DB)

	user, err := repo.FindUserByUsernameOrEmail(ctxA, usernameOrEmail)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusBadRequest)
		return
	}

	if j.sender == nil {

		http.Error(w, "Can't use this feature without mailing true in config", http.StatusConflict)
		return
	}

	code, err := utils.GenerateOTP(10, 6)

	if err != nil {

		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	codeHash := utils.HashToken(code)

	codeExpiresAt := time.Now().UTC().Add(time.Duration(j.mailingExpiration.ForgotPassExpiry))

	ctxB, cancelB := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelB()

	mfaId, err := repo.CreateMfaMail(ctxB, repository.CreateMfaMailParams{
		UserID:    user.ID,
		MfaType:   enums.MfaForgotPassword,
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
		ApiName: enums.MfaForgotPassword,
		Code:    code,
	}, mailing.User{
		Username:  user.Username,
		UserEmail: user.Email,
	})

	if err != nil {

		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Password-reset mail sent successfully!")
}
