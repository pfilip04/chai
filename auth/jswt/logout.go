package jswt

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/errs"
)

func (j *JWTAuth) Logout(w http.ResponseWriter, r *http.Request) {

	userID, sessionID, err := j.Authorize(r)

	if err != nil {

		http.Error(w, errs.AuthError.Err.Error(), http.StatusUnauthorized)
		return
	}

	ctxA, cancelA := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelA()

	tx, err := j.DB.Begin(ctxA)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	defer tx.Rollback(ctxA)

	repo := repository.New(tx)

	rows, err := repo.DeleteRefreshToken(ctxA, sessionID)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	if rows == 0 {

		http.Error(w, "No refresh token found/expired", http.StatusUnauthorized)
		return
	}

	rows, err = repo.DeleteJWTSession(ctxA, repository.DeleteJWTSessionParams{
		ID:     sessionID,
		UserID: userID,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	if rows == 0 {

		http.Error(w, "No session found/expired", http.StatusUnauthorized)
		return
	}

	if err := tx.Commit(ctxA); err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)

	fmt.Fprintln(w, "Logged out successfully")
}
