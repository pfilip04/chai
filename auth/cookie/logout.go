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

func (c *CookieAuth) Logout(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the User Authorization Tokens

	sessionID, err := c.Authorize(r)

	if err != nil {

		errs.WriteError(w, enums.Logout, err, "Cookie: Problem when Authorizing action", errs.AuthError)
		return
	}

	//
	// Clearing the Session, CSRF and Refresh Tokens in the DB

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	_, err = repo.DeleteCookieSession(ctxA, sessionID)

	if err != nil {

		errs.WriteError(w, enums.Logout, err, "Cookie: Problem when deleting the session in the db", errs.DatabaseError)
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

	fmt.Fprintln(w, "User logout successful")
}
