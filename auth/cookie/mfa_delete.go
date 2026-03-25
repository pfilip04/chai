package cookie

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
)

func (c *CookieAuth) DeleteMfa(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the MFA Authorization Token

	userID, err := c.MfaAuthorize(r)

	if err != nil {

		errs.WriteError(w, enums.MFADelete, err, "Cookie: Problem when Authorizing action", errs.AuthError)
		return
	}

	//
	// Deleting the User Account from the DB, that cascades to all session and refresh_tokens as well as mfa tables being deleted too

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	tx, err := c.DB.Begin(ctxA)

	if err != nil {

		errs.WriteError(w, enums.MFADelete, err, "Cookie: Transaction start error", errs.ServerError)
		return
	}

	defer tx.Rollback(ctxA)

	repo := repository.New(tx)

	rows, err := repo.ClearAllSessions(ctxA, userID)

	if err != nil {

		errs.WriteError(w, enums.MFADelete, err, "Cookie: Problem when clearing all user sessions", errs.DatabaseError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.MFADelete, errs.DatabaseError.Err, "Cookie: No user sessions deleted from the db", errs.DatabaseError)
		return
	}

	rows, err = repo.SoftDeleteUser(ctxA, userID)

	if err != nil {

		errs.WriteError(w, enums.MFADelete, err, "Cookie: Problem when deleting the user in the db", errs.DatabaseError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.MFADelete, errs.DatabaseError.Err, "Cookie: No user deleted from the db", errs.DatabaseError)
		return
	}

	rows, err = repo.ClearMfaSessions(ctxA, userID)

	if err != nil {

		errs.WriteError(w, enums.MFADelete, err, "Cookie: Couldn't delete mfa token in the db", errs.DatabaseError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.MFADelete, errs.DatabaseError.Err, "Cookie: No mfa token is deleted from the db", errs.DatabaseError)
		return
	}

	if err := tx.Commit(ctxA); err != nil {

		errs.WriteError(w, enums.MFADelete, err, "Cookie: Transaction commit error", errs.DatabaseError)
		return
	}

	//
	// Clearing the Cookies

	http.SetCookie(w, &http.Cookie{
		Name:     "mfa_session_token",
		Value:    "",
		Expires:  time.Now().UTC().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

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
