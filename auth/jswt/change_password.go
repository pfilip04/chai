package jswt

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
)

func (j *JWTAuth) ChangePassword(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the User Authorization Token

	userID, _, err := j.Authorize(r)

	if err != nil {

		http.Error(w, errs.AuthError.Err.Error(), http.StatusUnauthorized)
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

	//
	// Password Confirmation to procede

	if err != nil || !utils.CheckPasswordHash(password, user.PasswordHash) {

		http.Error(w, errs.AuthError.Err.Error(), http.StatusUnauthorized)
		return
	}

	//
	// New Password checking and Hashing

	if newPassword != newPasswordRepeat || !utils.IsValidPassword(newPassword) {

		http.Error(w, "Invalid password", http.StatusConflict)
		return
	}

	hashedNewPassword, err := utils.HashPassword(newPassword)

	if err != nil {

		http.Error(w, errs.ServerError.Err.Error(), errs.ServerError.Status)
		return
	}

	ctxB, cancelB := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelB()

	tx, err := j.DB.Begin(ctxB)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
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

	if err != nil || rows == 0 {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	//
	// Terminating all sessions

	rows, err = repo.ClearAllSessions(ctxB, userID)

	if err != nil || rows == 0 {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	if err := tx.Commit(ctxB); err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	fmt.Fprintln(w, "Password changed successfully")
}
