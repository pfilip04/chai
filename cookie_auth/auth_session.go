package cookie_auth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

var AuthError = errors.New("Unauthorized")

//
// Cookie checking for authorization

// Auth for GET

func (a *AuthService) SoftAuthorize(r *http.Request) error {

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" {
		return AuthError
	}

	sessionToken := st.Value

	var userID int

	ctx3, cancel3 := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel3()

	err = a.DB.QueryRow(ctx3,
		`SELECT id FROM users WHERE session_token=$1`,
		sessionToken,
	).Scan(&userID)

	if err != nil {
		return AuthError
	}

	return nil
}

// Auth for POST/PATCH/PUT/DELETE...

func (a *AuthService) HardAuthorize(r *http.Request) error {

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" {
		return AuthError
	}
	sessionToken := st.Value

	csrfToken := r.Header.Get("X-CSRF-Token")
	if csrfToken == "" {
		return AuthError
	}

	var dbCSRF string

	ctx3, cancel3 := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel3()

	err = a.DB.QueryRow(ctx3,
		`SELECT csrf_token FROM users WHERE session_token=$1`,
		sessionToken,
	).Scan(&dbCSRF)

	if err != nil {
		return AuthError
	}

	if dbCSRF != csrfToken {
		return AuthError
	}

	return nil
}
