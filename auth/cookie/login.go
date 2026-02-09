package cookie

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) Login(w http.ResponseWriter, r *http.Request) {

	//
	// Username and password check

	username := r.FormValue("username")
	password := r.FormValue("password")

	var id int
	var passwordHash string

	ctxA, cancelA := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelA()

	err := c.DB.QueryRow(ctxA,
		`SELECT id, password_hash FROM users WHERE username=$1`,
		username,
	).Scan(&id, &passwordHash)

	if err != nil || !utils.CheckPasswordHash(password, passwordHash) {
		er := http.StatusUnauthorized

		http.Error(w, "Invalid username or password", er)
		return
	}

	//
	// Generating and assigning session, csrf tokens to the user

	sessionToken, err := utils.GenerateToken(32)

	if err != nil {
		er := http.StatusInternalServerError

		http.Error(w, "Server error", er)
		return
	}

	csrfToken, err := utils.GenerateToken(32)

	if err != nil {
		er := http.StatusInternalServerError

		http.Error(w, "Server error", er)
		return
	}

	hashedSessionToken := utils.HashToken(sessionToken)
	hashedCsrfToken := utils.HashToken(csrfToken)

	ctxB, cancelB := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelB()

	_, err = c.DB.Exec(ctxB,
		`UPDATE users SET session_token=$1, csrf_token=$2 WHERE id=$3`,
		hashedSessionToken, hashedCsrfToken, id,
	)

	if err != nil {
		er := http.StatusInternalServerError

		http.Error(w, "Server error", er)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	fmt.Fprintln(w, "User login successful!")
}
