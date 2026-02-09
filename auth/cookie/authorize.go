package cookie

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/pfilip04/chai/utils"
)

var AuthError = errors.New("Unauthorized")

//
// Cookie checking for authorization

// Auth for GET

func (a *CookieAuth) SoftAuthorize(r *http.Request) (int, error) {

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" {
		return 0, AuthError
	}

	hashedSessionToken := utils.HashToken(st.Value)

	var userID int

	ctx3, cancel3 := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel3()

	err = a.DB.QueryRow(ctx3,
		`SELECT id FROM users WHERE session_token=$1`,
		hashedSessionToken,
	).Scan(&userID)

	if err != nil {
		return 0, AuthError
	}

	return userID, nil
}

// Auth for POST/PATCH/PUT/DELETE...

func (a *CookieAuth) HardAuthorize(r *http.Request) (int, error) {

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" {
		return 0, AuthError
	}

	hashedSessionToken := utils.HashToken(st.Value)

	csrfToken := r.Header.Get("X-CSRF-Token")

	if csrfToken == "" {
		return 0, AuthError
	}

	var dbCsrfToken string
	var userID int

	ctx3, cancel3 := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel3()

	err = a.DB.QueryRow(ctx3,
		`SELECT id, csrf_token FROM users WHERE session_token=$1`,
		hashedSessionToken,
	).Scan(&userID, &dbCsrfToken)

	if err != nil {
		return 0, AuthError
	}

	if !utils.CheckToken(csrfToken, dbCsrfToken) {
		return 0, AuthError
	}

	return userID, nil
}
