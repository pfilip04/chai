package jswt

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

func (j *JWTAuth) Delete(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the User Authorization Token

	userID, _, err := j.Authorize(r)

	if err != nil {

		errs.WriteError(w, enums.Delete, err, "JWT: Problem when Authorizing action", errs.AuthError)
		return
	}

	//
	// Finding the User in the DB

	ctxA, cancelA := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelA()

	repo := repository.New(j.DB)

	user, err := repo.GetUserById(ctxA, userID)

	if err != nil {

		errs.WriteError(w, enums.Delete, err, "JWT: Couldn't get user by user id from the db", errs.DatabaseError)
		return
	}

	//
	// Password Confirmation to procede

	password := r.FormValue("password")
	passwordRepeat := r.FormValue("password-repeat")

	if password != passwordRepeat {

		errs.WriteError(w, enums.Delete, errs.ConflictError.Err, "JWT: Password missmatch", errs.ConflictError)
		return
	}

	if !utils.CheckPasswordHash(password, user.PasswordHash) {

		errs.WriteError(w, enums.Delete, errs.AuthError.Err, "JWT: Incorrect password", errs.AuthError)
		return
	}

	//
	// Sending the mail

	if j.sender != nil && user.Mfa {

		message, err := mailing.SendMail(mailing.DbQuerying{
			Repo:         repo,
			QueryTimeout: j.queryTimeout,
			Ctx:          r.Context(),
		}, mailing.Mailc{
			MExp:    j.mailingExpiration.MfaDeleteExpiry,
			MailCfg: j.mailingExpiration,
		}, mailing.User{
			UserID:    userID,
			Username:  user.Username,
			UserEmail: user.Email,
		}, mailing.MfaType{
			ApiName:  enums.MfaDeleteVerify,
			MailName: "Delete",
		}, j.sender)

		if err != nil {

			errs.WriteError(w, enums.Delete, err, "JWT: Problem when sending the mail", errs.ServerError)
			return
		}

		fmt.Fprintln(w, message)
		return
	}

	//
	// Deleting the User Account from the DB, that cascades to all session and refresh_tokens being deleted too

	ctxB, cancelB := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelB()

	tx, err := j.DB.Begin(ctxB)

	if err != nil {

		errs.WriteError(w, enums.Delete, err, "JWT: Transaction start error", errs.ServerError)
		return
	}

	defer tx.Rollback(ctxB)

	repo = repository.New(tx)

	rows, err := repo.ClearAllSessions(ctxB, userID)

	if err != nil {

		errs.WriteError(w, enums.Delete, err, "JWT: Problem when clearing all user sessions", errs.DatabaseError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.Delete, errs.DatabaseError.Err, "JWT: No user sessions deleted from the db", errs.DatabaseError)
		return
	}

	rows, err = repo.SoftDeleteUser(ctxB, userID)

	if err != nil {

		errs.WriteError(w, enums.Delete, err, "JWT: Problem when deleting the user in the db", errs.DatabaseError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.Delete, errs.DatabaseError.Err, "JWT: No user deleted from the db", errs.DatabaseError)
		return
	}

	if err := tx.Commit(ctxB); err != nil {

		errs.WriteError(w, enums.Delete, err, "JWT: Transaction commit error", errs.DatabaseError)
		return
	}

	w.WriteHeader(http.StatusOK)

	fmt.Fprintln(w, "User account deletion successful")
}
