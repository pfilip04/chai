package cookie

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

func (c *CookieAuth) Delete(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the User Authorization Tokens

	sessionID, err := c.Authorize(r)

	if err != nil {

		errs.WriteError(w, enums.Delete, err, "Cookie: Problem when Authorizing action", errs.AuthError)
		return
	}

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	//
	// Finding the User in the DB

	userID, err := repo.GetUserIdBySessionId(ctxA, sessionID)

	if err != nil {

		errs.WriteError(w, enums.Delete, err, "Cookie: Couldn't get user id by session id from the db", errs.DatabaseError)
		return
	}

	ctxB, cancelB := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelB()

	user, err := repo.GetUserById(ctxB, userID)

	if err != nil {

		errs.WriteError(w, enums.Delete, err, "Cookie: Couldn't get user by user id from the db", errs.DatabaseError)
		return
	}

	//
	// Password Confirmation to procede

	password := r.FormValue("password")
	passwordRepeat := r.FormValue("password-repeat")

	if password != passwordRepeat {

		errs.WriteError(w, enums.Delete, errs.ConflictError.Err, "Cookie: Password missmatch", errs.ConflictError)
		return
	}

	if !utils.CheckPasswordHash(password, user.PasswordHash) {

		errs.WriteError(w, enums.Delete, errs.AuthError.Err, "Cookie: Incorrect password", errs.AuthError)
		return
	}

	//
	// Sending the mail

	if c.sender != nil && user.Mfa {

		message, err := mailing.SendMail(mailing.DbQuerying{
			Repo:         repo,
			QueryTimeout: c.queryTimeout,
			Ctx:          r.Context(),
		}, mailing.Mailc{
			MExp:    c.mailingExpiration.MfaDeleteExpiry,
			MailCfg: c.mailingExpiration,
		}, mailing.User{
			UserID:    userID,
			Username:  user.Username,
			UserEmail: user.Email,
		}, mailing.MfaType{
			ApiName:  enums.MfaDeleteVerify,
			MailName: "Delete",
		}, c.sender)

		if err != nil {

			errs.WriteError(w, enums.Delete, err, "Cookie: Problem when sending the mail", errs.ServerError)
			return
		}

		fmt.Fprintln(w, message)
		return
	}

	//
	// Deleting the User Account from the DB, that cascades to all session and refresh_tokens being deleted too

	ctxC, cancelC := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelC()

	tx, err := c.DB.Begin(ctxC)

	if err != nil {

		errs.WriteError(w, enums.Delete, err, "Cookie: Transaction start error", errs.ServerError)
		return
	}

	defer tx.Rollback(ctxC)

	repo = repository.New(tx)

	rows, err := repo.ClearAllSessions(ctxC, userID)

	if err != nil {

		errs.WriteError(w, enums.Delete, err, "Cookie: Problem when clearing all user sessions", errs.DatabaseError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.Delete, errs.DatabaseError.Err, "Cookie: No user sessions deleted from the db", errs.DatabaseError)
		return
	}

	rows, err = repo.SoftDeleteUser(ctxC, userID)

	if err != nil {

		errs.WriteError(w, enums.Delete, err, "Cookie: Problem when soft deleting the user in the db", errs.DatabaseError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.Delete, errs.DatabaseError.Err, "Cookie: No user soft deleted from the db", errs.DatabaseError)
		return
	}

	if err := tx.Commit(ctxC); err != nil {

		errs.WriteError(w, enums.Delete, err, "Cookie: Transaction commit error", errs.DatabaseError)
		return
	}

	//
	// Clearing the Cookies

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().UTC().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().UTC().Add(-time.Hour),
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Expires:  time.Now().UTC().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	fmt.Fprintln(w, "User account deletion successful")
}
