package cookie

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/mailing"
)

func (c *CookieAuth) ForgotPassword(w http.ResponseWriter, r *http.Request) {

	//
	// Finding the User in the DB

	usernameOrEmail := r.FormValue("username_or_email")

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	user, err := repo.FindUserByUsernameOrEmail(ctxA, usernameOrEmail)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusBadRequest)
		return
	}

	//
	// If Mailing wasn't specified in the JSON then the endpoint can't be used, otherwise Send Mail

	if c.sender == nil {

		http.Error(w, "Can't use this feature without mailing true in config", http.StatusConflict)
		return
	}

	message, err := mailing.SendMail(mailing.DbQuerying{
		Repo:         repo,
		QueryTimeout: c.queryTimeout,
		Ctx:          r.Context(),
	}, mailing.Mailc{
		MExp:    c.mailingExpiration.ForgotPassExpiry,
		MailCfg: c.mailingExpiration,
	}, mailing.User{
		UserID:    user.ID,
		Username:  user.Username,
		UserEmail: user.Email,
	}, mailing.MfaType{
		ApiName:  enums.MfaForgotPassword,
		MailName: enums.PassReset,
	}, c.sender)

	if err != nil {

		http.Error(w, errs.ServerError.Err.Error(), errs.ServerError.Status)
		return
	}

	fmt.Fprintln(w, message)
}
