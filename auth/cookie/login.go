package cookie

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) Login(w http.ResponseWriter, r *http.Request) {

	//
	// Username and password check

	username := r.FormValue("username")
	password := r.FormValue("password")

	var userID uuid.UUID
	var passwordHash string

	ctxA, cancelA := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelA()

	err := c.DB.QueryRow(ctxA,
		`SELECT id, password_hash FROM users 
		WHERE username=$1`,
		username,
	).Scan(&userID, &passwordHash)

	if err != nil || !utils.CheckPasswordHash(password, passwordHash) {

		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	//
	// Generating and assigning session to the user

	sessionToken, err := utils.GenerateToken(32)

	if err != nil {

		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	for !c.CheckUniqueSession(r, sessionToken) {
		sessionToken, err = utils.GenerateToken(32)

		if err != nil {

			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
	}

	csrfToken, err := utils.GenerateToken(32)

	if err != nil {

		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	hashedSessionToken := utils.HashToken(sessionToken)
	hashedCsrfToken := utils.HashToken(csrfToken)

	expiresAt := time.Now().Add(24 * time.Hour)

	ctxB, cancelB := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelB()

	_, err = c.DB.Exec(ctxB,
		`INSERT INTO sessions 
        (user_id, session_token, csrf_token, platform, expires_at) 
        VALUES ($1, $2, $3, $4, $5)`,
		userID,
		hashedSessionToken,
		hashedCsrfToken,
		"web",
		expiresAt,
	)

	if err != nil {

		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  expiresAt,
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	fmt.Fprintln(w, "User login successful!")
}
