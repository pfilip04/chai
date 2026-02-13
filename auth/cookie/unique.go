package cookie

import (
	"context"
	"net/http"

	"github.com/pfilip04/chai/utils"
)

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
