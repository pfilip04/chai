package cookie

import (
	"context"
	"net/http"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
)

func (c *CookieAuth) RegisterMfa(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the MFA Authorization Token

	userId, err := c.MfaAuthorize(r)

	if err != nil {

		errs.WriteError(w, enums.RegisterMFA, err, "Cookie: Problem when Authorizing action", errs.AuthError)
		return
	}

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	tx, err := c.DB.Begin(ctxA)

	if err != nil {

		errs.WriteError(w, enums.RegisterMFA, err, "Cookie: Transaction start error", errs.ServerError)
		return
	}

	defer tx.Rollback(ctxA)

	repo := repository.New(tx)

	rows, err := repo.VerifyEmail(ctxA, userId)

	if err != nil {

		errs.WriteError(w, enums.RegisterMFA, err, "Cookie: Couldn't complete the email verification in the db", errs.DatabaseError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.RegisterMFA, errs.DatabaseError.Err, "Cookie: No email verified in the db", errs.DatabaseError)
		return
	}

	//
	// Clearing the MFA Token in the DB

	rows, err = repo.ClearMfaSessions(ctxA, userId)

	if err != nil {

		errs.WriteError(w, enums.RegisterMFA, err, "Cookie: Couldn't delete mfa token in the db", errs.DatabaseError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.RegisterMFA, errs.DatabaseError.Err, "Cookie: No mfa token is deleted from the db", errs.DatabaseError)
		return
	}

	if err := tx.Commit(ctxA); err != nil {

		errs.WriteError(w, enums.RegisterMFA, err, "Cookie: Transaction commit error", errs.DatabaseError)
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
