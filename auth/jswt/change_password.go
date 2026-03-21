package jswt

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
)

func (j *JWTAuth) ChangePassword(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the User Authorization Token

	userID, _, err := j.Authorize(r)

	if err != nil {

		errs.WriteError(w, enums.ChangePassword, err, "JWT: Problem when Authorizing action", errs.AuthError)
		return
	}

	//
	// Extracting Form Values

	password := r.FormValue("old-password")

	newPassword := r.FormValue("new_password")
	newPasswordRepeat := r.FormValue("new_password_repeat")

	ctxA, cancelA := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelA()

	repo := repository.New(j.DB)

	//
	// Finding the User in the DB

	user, err := repo.GetUserById(ctxA, userID)

	if err != nil {

		errs.WriteError(w, enums.ChangePassword, err, "JWT: Couldn't get user by user id from the db", errs.DatabaseError)
		return
	}

	//
	// Password Confirmation to procede

	if !utils.CheckPasswordHash(password, user.PasswordHash) {

		errs.WriteError(w, enums.ChangePassword, errs.AuthError.Err, "JWT: Incorrect password", errs.AuthError)
		return
	}

	//
	// New Password checking and Hashing

	if newPassword != newPasswordRepeat {

		errs.WriteError(w, enums.ChangePassword, errs.ConflictError.Err, "JWT: Password missmatch", errs.ConflictError)
		return
	}

	if !utils.IsValidPassword(newPassword) {

		errs.WriteError(w, enums.ChangePassword, errs.AuthError.Err, "JWT: Invalid password", errs.AuthError)
		return
	}

	hashedNewPassword, err := utils.HashPassword(newPassword)

	if err != nil {

		errs.WriteError(w, enums.ChangePassword, err, "JWT: Could't hash password", errs.ServerError)
		return
	}

	ctxB, cancelB := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelB()

	tx, err := j.DB.Begin(ctxB)

	if err != nil {

		errs.WriteError(w, enums.ChangePassword, err, "JWT: Transaction start error", errs.ServerError)
		return
	}

	defer tx.Rollback(ctxB)

	repo = repository.New(tx)

	//
	// Updating User Password

	rows, err := repo.UpdateUserPassword(ctxB, repository.UpdateUserPasswordParams{
		PasswordHash: hashedNewPassword,
		UpdatedAt:    time.Now().UTC(),
		ID:           userID,
	})

	if err != nil {

		errs.WriteError(w, enums.ChangePassword, err, "JWT: Problem when updating user password in the db", errs.DatabaseError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.ChangePassword, errs.DatabaseError.Err, "JWT: No user password updated in the db", errs.DatabaseError)
		return
	}

	//
	// Terminating all sessions

	rows, err = repo.ClearAllSessions(ctxB, userID)

	if err != nil {

		errs.WriteError(w, enums.ChangePassword, err, "JWT: Couldn't delete all user sessions in the db", errs.DatabaseError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.ChangePassword, errs.DatabaseError.Err, "JWT: No user sessions deleted from the db", errs.DatabaseError)
		return
	}

	if err := tx.Commit(ctxB); err != nil {

		errs.WriteError(w, enums.PasswordReset, err, "JWT: Transaction commit error", errs.DatabaseError)
		return
	}

	fmt.Fprintln(w, "Password changed successfully")
}
