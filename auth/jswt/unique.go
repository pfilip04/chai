package jswt

import (
	"context"
	"net/http"
)

func (j *JWTAuth) CheckUniqueUsername(r *http.Request, username string) bool {

	var count int

	ctxA, cancelA := context.WithTimeout(r.Context(), j.QueryTimeout)
	defer cancelA()

	err := j.DB.QueryRow(ctxA,
		`SELECT COUNT(*) FROM users 
		WHERE username=$1`,
		username,
	).Scan(&count)

	if err != nil {
		return false
	}

	return count == 0
}

func (j *JWTAuth) CheckUniqueEmail(r *http.Request, email string) bool {

	var count int

	ctxA, cancelA := context.WithTimeout(r.Context(), j.QueryTimeout)
	defer cancelA()

	err := j.DB.QueryRow(ctxA,
		`SELECT COUNT(*) FROM users 
		WHERE email=$1`,
		email,
	).Scan(&count)

	if err != nil {
		return false
	}

	return count == 0
}
