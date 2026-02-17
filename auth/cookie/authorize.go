package cookie

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/pfilip04/chai/errs"
	"github.com/pfilip04/chai/utils"
)

//
// Cookie checking for authorization

// Auth for GET

func (c *CookieAuth) SoftAuthorize(r *http.Request) (uuid.UUID, error) {

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" {
		return uuid.Nil, errs.AuthError
	}

	hashedSessionToken := utils.HashToken(st.Value)

	var userID uuid.UUID

	ctxA, cancelA := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelA()

	err = c.DB.QueryRow(ctxA,
		`SELECT user_id FROM sessions 
		WHERE session_token=$1 AND expires_at > NOW()`,
		hashedSessionToken,
	).Scan(&userID)

	if err != nil {
		return uuid.Nil, errs.AuthError
	}

	return userID, nil
}

// Auth for POST/PATCH/PUT/DELETE...

func (c *CookieAuth) HardAuthorize(r *http.Request) (uuid.UUID, error) {

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" {
		return uuid.Nil, errs.AuthError
	}

	hashedSessionToken := utils.HashToken(st.Value)

	csrfToken := r.Header.Get("X-CSRF-Token")

	if csrfToken == "" {
		return uuid.Nil, errs.AuthError
	}

	var dbCsrfToken string
	var userID uuid.UUID

	ctxA, cancelA := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelA()

	err = c.DB.QueryRow(ctxA,
		`SELECT user_id, csrf_token FROM sessions 
		WHERE session_token=$1 AND expires_at > NOW()`,
		hashedSessionToken,
	).Scan(&userID, &dbCsrfToken)

	if err != nil {
		return uuid.Nil, errs.AuthError
	}

	if !utils.CheckToken(csrfToken, dbCsrfToken) {
		return uuid.Nil, errs.AuthError
	}

	return userID, nil
}
