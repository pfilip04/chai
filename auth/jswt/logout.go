package jswt

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
)

func (j *JWTAuth) Logout(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the User Authorization Token

	_, sessionID, err := j.Authorize(r)

	if err != nil {

		errs.WriteError(w, enums.Logout, err, "JWT: Problem when Authorizing action", errs.AuthError)
		return
	}

	//
	// Clearing the Session, CSRF and Refresh Tokens in the DB

	ctxA, cancelA := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelA()

	repo := repository.New(j.DB)

	rows, err := repo.DeleteJWTSession(ctxA, sessionID)

	if err != nil {

		errs.WriteError(w, enums.Logout, err, "JWT: Problem when deleting the session in the db", errs.DatabaseError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.Logout, errs.DatabaseError.Err, "JWT: No session deleted from the db", errs.DatabaseError)
		return
	}

	w.WriteHeader(http.StatusOK)

	fmt.Fprintln(w, "Logged out successfully")
}
