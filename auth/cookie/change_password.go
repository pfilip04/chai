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

		errs.WriteError(w, enums.ChangePassword, err, "Cookie: Problem when Authorizing action", errs.AuthError)
		return
	}

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	//
	// Finding the User in the DB

	userID, err := repo.GetUserIdBySessionId(ctxA, sessionID)

	if err != nil {

		errs.WriteError(w, enums.ChangePassword, err, "Cookie: Couldn't get user id by session id from the db", errs.DatabaseError)
		return
	}

	ctxB, cancelB := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelB()

	user, err := repo.GetUserById(ctxB, userID)

	if err != nil {

		errs.WriteError(w, enums.ChangePassword, err, "Cookie: Couldn't get user by user id from the db", errs.DatabaseError)
		return
	}

	//
	// Password Confirmation to procede

	password := r.FormValue("old-password")

	if !utils.CheckPasswordHash(password, user.PasswordHash) {

		errs.WriteError(w, enums.ChangePassword, errs.AuthError.Err, "Cookie: Incorrect password", errs.AuthError)
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
			MailName: "Password-change",
		}, c.sender)

		if err != nil {

			errs.WriteError(w, enums.ChangePassword, err, "Cookie: Problem when sending the mail", errs.ServerError)
			return
		}

		fmt.Fprintln(w, message)
	}
}
