package cookie

import (
	"context"
	"net/http"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) PasswordReset(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the MFA Authorization Token

	userId, err := c.MfaAuthorize(r)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	//
	// Extracting Form Values

	newPassword := r.FormValue("new_password")
	newPasswordRepeat := r.FormValue("new_password_repeat")

	//
	// Password checking and Hashing

	if newPassword != newPasswordRepeat || !utils.IsValidPassword(newPassword) {

		http.Error(w, "Invalid password", http.StatusConflict)
		return
	}

	hashedNewPassword, err := utils.HashPassword(newPassword)

	if err != nil {

		http.Error(w, errs.ServerError.Err.Error(), errs.ServerError.Status)
		return
	}

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	tx, err := c.DB.Begin(ctxA)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	defer tx.Rollback(ctxA)

	repo := repository.New(tx)

	//
	// Updating User Password

	rows, err := repo.UpdateUserPassword(ctxA, repository.UpdateUserPasswordParams{
		PasswordHash: hashedNewPassword,
		UpdatedAt:    time.Now().UTC(),
		ID:           userId,
	})

	if err != nil || rows == 0 {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	//
	// Clearing the MFA Token in the DB

	rows, err = repo.ClearMfaSessions(ctxA, userId)

	if err != nil || rows == 0 {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	if err := tx.Commit(ctxA); err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	//
	// Clearing the MFA Cookie

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
