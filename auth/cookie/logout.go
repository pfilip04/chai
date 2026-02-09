package cookie

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) Logout(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the user authorization tokens

	if _, err := c.HardAuthorize(r); err != nil {
		er := http.StatusUnauthorized

		http.Error(w, "Unauthorized", er)
		return
	}

	//
	// Clearing the session and CSRF tokens in the database

	sessionCookie, err := r.Cookie("session_token")

	if err != nil {
		er := http.StatusUnauthorized

		http.Error(w, "Unauthorized", er)
		return
	}

	hashedSessionToken := utils.HashToken(sessionCookie.Value)

	ctxA, cancelA := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelA()

	_, err = c.DB.Exec(ctxA,
		`UPDATE users SET session_token=NULL, csrf_token=NULL WHERE session_token=$1`,
		hashedSessionToken,
	)

	if err != nil {
		er := http.StatusInternalServerError

		http.Error(w, "Server error", er)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	fmt.Fprintln(w, "User logout successful")
}
