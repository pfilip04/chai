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

	tx, err := c.DB.Begin(ctxA)

	if err != nil {

		errs.WriteError(w, enums.Delete, err, "Cookie: Transaction start error", errs.ServerError)
		return
	}

	defer tx.Rollback(ctxA)

	repo := repository.New(tx)

	//
	// Deleting the Session, CSRF and Refresh Tokens alongside the User Account from the DB

	userID, err := repo.DeleteCookieSession(ctxA, sessionID)

	if err != nil {

		errs.WriteError(w, enums.Delete, err, "Cookie: Problem when deleting the session in the db", errs.DatabaseError)
		return
	}

	rows, err := repo.DeleteUser(ctxA, userID)

	if err != nil {

		errs.WriteError(w, enums.Delete, err, "Cookie: Problem when deleting the user in the db", errs.DatabaseError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.Delete, errs.DatabaseError.Err, "Cookie: No user deleted from the db", errs.DatabaseError)
		return
	}

	if err := tx.Commit(ctxA); err != nil {

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
