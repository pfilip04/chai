package cookie_auth

import (
	"errors"
	"net/http"
)

var AuthError = errors.New("Unauthorized")

//
// Cookie checking for authorization

func (a *AuthService) Authorize(r *http.Request) error {

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
	err = a.DB.QueryRow(r.Context(),
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
