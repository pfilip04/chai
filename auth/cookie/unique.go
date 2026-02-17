package cookie

import (
	"context"
	"net/http"
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
