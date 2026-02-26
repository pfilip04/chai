package cookie

import (
	"context"
	"net/http"

	"github.com/pfilip04/chai/database/postgresql/repository"
)

func (c *CookieAuth) CheckUniqueUsername(r *http.Request, username string) bool {

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	count, err := repo.CountUsername(ctxA, username)

	if err != nil {
		return false
	}

	return count == 0
}

func (c *CookieAuth) CheckUniqueEmail(r *http.Request, email string) bool {

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	count, err := repo.CountEmail(ctxA, email)

	if err != nil {
		return false
	}

	return count == 0
}
