package jswt

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/pfilip04/chai/errs"
	"github.com/pfilip04/chai/utils"
)

func (j *JWTAuth) Logout(w http.ResponseWriter, r *http.Request) {

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

	_, err = j.DB.Exec(ctxA,
		`DELETE FROM sessions 
		WHERE id=$1 AND user_id=$2`,
		sessionID,
		userID,
	)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	ctxB, cancelB := context.WithTimeout(r.Context(), j.QueryTimeout)
	defer cancelB()

	_, err = j.DB.Exec(ctxB,
		`DELETE FROM refresh_tokens 
		WHERE session_id=$1`,
		sessionID,
	)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)

	fmt.Fprintln(w, "Logged out successfully")
}
