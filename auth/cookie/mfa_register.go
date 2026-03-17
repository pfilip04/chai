package cookie

import (
	"context"
	"net/http"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/errs"
)

func (c *CookieAuth) MfaRegister(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the MFA Authorization Token

	userId, err := c.MfaAuthorize(r)

	if err != nil {

		http.Error(w, errs.AuthError.Err.Error(), errs.AuthError.Status)
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

	rows, err := repo.VerifyEmail(ctxA, userId)

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
