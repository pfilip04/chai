package jswt

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/errs"
	"github.com/pfilip04/chai/utils"
)

func (j *JWTAuth) Delete(w http.ResponseWriter, r *http.Request) {

	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {

		http.Error(w, errs.AuthError.Error(), http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	userID, sessionID, err := utils.CheckJWT(token, j.secret, j.issuer)

	if err != nil {

		http.Error(w, errs.AuthError.Error(), http.StatusUnauthorized)
		return
	}

	ctxA, cancelA := context.WithTimeout(r.Context(), j.QueryTimeout)
	defer cancelA()

	tx, err := j.DB.Begin(ctxA)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	defer tx.Rollback(ctxA)

	repo := repository.New(tx)

	rows, err := repo.DeleteRefreshToken(ctxA, sessionID)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
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

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	if rows == 0 {

		http.Error(w, "No session found/expired", http.StatusUnauthorized)
		return
	}

	rows, err = repo.DeleteUser(ctxA, userID)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	if rows == 0 {

		http.Error(w, "No user found to delete", http.StatusUnauthorized)
		return
	}

	if err := tx.Commit(ctxA); err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "User account deletion successful")
}
