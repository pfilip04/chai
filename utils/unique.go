package utils

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pfilip04/chai/database/postgresql/repository"
)

//
// Checking if the username exists in the database - if not, it is available therefore it returns true otherwise false

func CheckUniqueUsername(r *http.Request, username string, db *pgxpool.Pool, timeout time.Duration) bool {

	ctxA, cancelA := context.WithTimeout(r.Context(), timeout)
	defer cancelA()

	repo := repository.New(db)

	count, err := repo.CountUsername(ctxA, username)

	if err != nil {

		return false
	}

	return count == 0
}

//
// Checking if the email exists in the database - if not, it is available therefore it returns true otherwise false

func CheckUniqueEmail(r *http.Request, email string, db *pgxpool.Pool, timeout time.Duration) bool {

	ctxA, cancelA := context.WithTimeout(r.Context(), timeout)
	defer cancelA()

	repo := repository.New(db)

	count, err := repo.CountEmail(ctxA, email)

	if err != nil {

		return false
	}

	return count == 0
}
