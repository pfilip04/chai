package jswt

import (
	"context"
	"net/http"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
)

func (j *JWTAuth) PasswordReset(w http.ResponseWriter, r *http.Request) {

	userId, err := j.MfaAuthorize(r)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	newPassword := r.FormValue("new_password")
	newPasswordRepeat := r.FormValue("new_password_repeat")

	if newPassword != newPasswordRepeat || !utils.IsValidPassword(newPassword) {

		http.Error(w, "Invalid password", http.StatusConflict)
		return
	}

	hashedNewPassword, err := utils.HashPassword(newPassword)

	if err != nil {

		http.Error(w, errs.ServerError.Err.Error(), errs.ServerError.Status)
		return
	}

	ctxA, cancelA := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelA()

	tx, err := j.DB.Begin(ctxA)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	defer tx.Rollback(ctxA)

	repo := repository.New(tx)

	rows, err := repo.ClearMfaMail(ctxA, userId)

	if err != nil || rows == 0 {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	rows, err = repo.UpdateUserPassword(ctxA, repository.UpdateUserPasswordParams{
		PasswordHash: hashedNewPassword,
		UpdatedAt:    time.Now().UTC(),
		ID:           userId,
	})

	if err != nil || rows == 0 {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	if err := tx.Commit(ctxA); err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "mfa_session_token",
		Value:    "",
		Expires:  time.Now().UTC().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
}
