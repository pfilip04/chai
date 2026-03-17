package jswt

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/errs"
)

func (j *JWTAuth) Logout(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the User Authorization Token

	_, sessionID, err := j.Authorize(r)

	if err != nil {

		http.Error(w, errs.AuthError.Err.Error(), http.StatusUnauthorized)
		return
	}

	//
	// Clearing the Session, CSRF and Refresh Tokens in the DB

	ctxA, cancelA := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelA()

	repo := repository.New(j.DB)

	rows, err := repo.DeleteJWTSession(ctxA, sessionID)

	if err != nil || rows == 0 {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	w.WriteHeader(http.StatusOK)

	fmt.Fprintln(w, "Logged out successfully")
}
