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

		errs.WriteError(w, enums.ForgotPassword, err, "JWT: Incorrect username or email", errs.AuthError)
		return
	}

	//
	// If Mailing wasn't specified in the JSON then the endpoint can't be used, otherwise Send Mail

	if j.sender == nil {

		errs.WriteError(w, enums.ForgotPassword, errs.BadRequestError.Err, "JWT: Can't use this feature without mailing true in config", errs.BadRequestError)
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
		MailName: "Password-reset",
	}, j.sender)

	if err != nil {

		errs.WriteError(w, enums.ForgotPassword, err, "JWT: Problem when sending the mail", errs.ServerError)
		return
	}

	fmt.Fprintln(w, message)
}
