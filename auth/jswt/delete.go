package jswt

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
)

func (j *JWTAuth) Delete(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the User Authorization Token

	userID, sessionID, err := j.Authorize(r)

	if err != nil {

		errs.WriteError(w, enums.Delete, err, "JWT: Problem when Authorizing action", errs.AuthError)
		return
	}

	//
	// Deleting the Session alongside the User Account from the DB

	ctxA, cancelA := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelA()

	tx, err := j.DB.Begin(ctxA)

	if err != nil {

		errs.WriteError(w, enums.Delete, err, "JWT: Transaction start error", errs.ServerError)
		return
	}

	defer tx.Rollback(ctxA)

	repo := repository.New(tx)

	rows, err := repo.DeleteJWTSession(ctxA, sessionID)

	if err != nil {

		errs.WriteError(w, enums.Delete, err, "JWT: Problem when deleting the session in the db", errs.DatabaseError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.Logout, errs.DatabaseError.Err, "JWT: No session deleted", errs.DatabaseError)
		return
	}

	rows, err = repo.DeleteUser(ctxA, userID)

	if err != nil {

		errs.WriteError(w, enums.Delete, err, "JWT: Problem when deleting the user in the db", errs.DatabaseError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.Delete, errs.DatabaseError.Err, "JWT: No user deleted from the db", errs.DatabaseError)
		return
	}

	if err := tx.Commit(ctxA); err != nil {

		errs.WriteError(w, enums.Delete, err, "JWT: Transaction commit error", errs.DatabaseError)
		return
	}

	w.WriteHeader(http.StatusOK)

	fmt.Fprintln(w, "User account deletion successful")
}
