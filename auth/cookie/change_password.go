package cookie

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/mailing"
	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) ChangePassword(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the User Authorization Tokens

	sessionID, err := c.Authorize(r)

	if err != nil {

		http.Error(w, errs.AuthError.Err.Error(), http.StatusUnauthorized)
		return
	}

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	//
	// Finding the User in the DB

	userID, err := repo.GetUserIdBySessionId(ctxA, sessionID)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	ctxB, cancelB := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelB()

	user, err := repo.GetUserById(ctxB, userID)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	//
	// Password Confirmation to procede

	password := r.FormValue("old-password")

	if !utils.CheckPasswordHash(password, user.PasswordHash) {

		http.Error(w, errs.AuthError.Err.Error(), http.StatusUnauthorized)
		return
	}

	//
	// If Mailing was specified in the JSON and if the User opted for MFA then Send Mail

	if c.sender != nil && user.Mfa {

		message, err := mailing.SendMail(mailing.DbQuerying{
			Repo:         repo,
			QueryTimeout: c.queryTimeout,
			Ctx:          r.Context(),
		}, mailing.Mailc{
			MExp:    c.mailingExpiration.ChangePassExpiry,
			MailCfg: c.mailingExpiration,
		}, mailing.User{
			UserID:    userID,
			Username:  user.Username,
			UserEmail: user.Email,
		}, mailing.MfaType{
			ApiName:  enums.MfaChangePassword,
			MailName: enums.PassChange,
		}, c.sender)

		if err != nil {

			http.Error(w, errs.ServerError.Err.Error(), errs.ServerError.Status)
			return
		}

		fmt.Fprintln(w, message)
	}
}
