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

	csrfToken, err := utils.GenerateToken(32)

	if err != nil {

		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	hashedSessionToken := utils.HashToken(sessionToken)
	hashedCsrfToken := utils.HashToken(csrfToken)

	var sessionID uuid.UUID
	expiresAt := time.Now().Add(24 * time.Hour)

	ctxB, cancelB := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelB()

	err = c.DB.QueryRow(ctxB,
		`INSERT INTO sessions 
        (user_id, session_token, csrf_token, platform, expires_at) 
        VALUES ($1, $2, $3, $4, $5) 
		RETURNING id`,
		userID,
		hashedSessionToken,
		hashedCsrfToken,
		"web",
		expiresAt,
	).Scan(&sessionID)

	if err != nil {

		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	refreshToken, err := utils.GenerateToken(64)

	if err != nil {

		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	hashedRefresh := utils.HashToken(refreshToken)

	ctxC, cancelC := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelC()

	_, err = c.DB.Exec(ctxC,
		`INSERT INTO refresh_tokens (session_id, refresh_token, expires_at) 
		VALUES ($1, $2, $3)`,
		sessionID,
		hashedRefresh,
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

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	fmt.Fprintln(w, "User login successful!")
}
