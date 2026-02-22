package jswt

import (
	"context"
	"net/http"

	"github.com/pfilip04/chai/database/postgresql/repository"
)

func (j *JWTAuth) CheckUniqueUsername(r *http.Request, username string) bool {

	ctxA, cancelA := context.WithTimeout(r.Context(), j.QueryTimeout)
	defer cancelA()

	repo := repository.New(j.DB)

	count, err := repo.CountUsername(ctxA, username)

	if err != nil {
		return false
	}

	return count == 0
}

func (j *JWTAuth) CheckUniqueEmail(r *http.Request, email string) bool {

	ctxA, cancelA := context.WithTimeout(r.Context(), j.QueryTimeout)
	defer cancelA()

	repo := repository.New(j.DB)

	count, err := repo.CountEmail(ctxA, email)

	if err != nil {
		return false
	}

	return count == 0
}
