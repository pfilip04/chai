package cookie

import (
	"context"
	"net/http"

	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) CheckUniqueUsername(r *http.Request, username string) bool {

	var count int

	ctxA, cancelA := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelA()

	err := c.DB.QueryRow(ctxA,
		`SELECT COUNT(*) FROM users 
		WHERE username=$1`,
		username,
	).Scan(&count)

	if err != nil {
		return false
	}

	return count == 0
}

func (c *CookieAuth) CheckUniqueEmail(r *http.Request, email string) bool {

	var count int

	ctxA, cancelA := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelA()

	err := c.DB.QueryRow(ctxA,
		`SELECT COUNT(*) FROM users 
		WHERE email=$1`,
		email,
	).Scan(&count)

	if err != nil {
		return false
	}

	return count == 0
}

func (c *CookieAuth) CheckUniqueSession(r *http.Request, token string) bool {

	hashedToken := utils.HashToken(token)

	var count int

	ctxA, cancelA := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelA()

	err := c.DB.QueryRow(ctxA,
		`SELECT COUNT(*) FROM sessions 
		WHERE session_token=$1`,
		hashedToken,
	).Scan(&count)

	if err != nil {
		return false
	}

	return count == 0
}

func (c *CookieAuth) CheckUniqueRefresh(r *http.Request, token string) bool {

	hashedToken := utils.HashToken(token)

	var count int

	ctxA, cancelA := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelA()

	err := c.DB.QueryRow(ctxA,
		`SELECT COUNT(*) FROM refresh_tokens 
		WHERE refresh_token=$1`,
		hashedToken,
	).Scan(&count)

	if err != nil {
		return false
	}

	return count == 0
}
