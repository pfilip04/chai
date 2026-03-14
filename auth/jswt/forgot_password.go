package jswt

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/mailing"
)

func (j *JWTAuth) ForgotPassword(w http.ResponseWriter, r *http.Request) {

	//
	// Finding the User in the DB

	usernameOrEmail := r.FormValue("username_or_email")

	ctxA, cancelA := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelA()

	repo := repository.New(j.DB)

	user, err := repo.FindUserByUsernameOrEmail(ctxA, usernameOrEmail)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusBadRequest)
		return
	}

	//
	// If Mailing wasn't specified in the JSON then the endpoint can't be used, otherwise Send Mail

	if j.sender == nil {

		http.Error(w, "Can't use this feature without mailing true in config", http.StatusConflict)
		return
	}

	message, err := mailing.SendMail(mailing.DbQuerying{
		Repo:         repo,
		QueryTimeout: j.queryTimeout,
		Ctx:          r.Context(),
	}, mailing.Mailc{
		MExp:    j.mailingExpiration.ForgotPassExpiry,
		MailCfg: j.mailingExpiration,
	}, mailing.User{
		UserID:    user.ID,
		Username:  user.Username,
		UserEmail: user.Email,
	}, mailing.MfaType{
		ApiName:  enums.MfaForgotPassword,
		MailName: enums.PassReset,
	}, j.sender)

	if err != nil {

		http.Error(w, errs.ServerError.Err.Error(), errs.ServerError.Status)
		return
	}

	fmt.Fprintln(w, message)
}
