package jswt

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/pfilip04/chai/utils"
)

func (j *JWTAuth) Delete(w http.ResponseWriter, r *http.Request) {

	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {

		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	userID, sessionID, err := utils.CheckJWT(token, j.secret, j.specialname)

	if err != nil {

		http.Error(w, "Unauthorized", http.StatusUnauthorized)
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

		http.Error(w, "Server error", http.StatusInternalServerError)
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

		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	ctxC, cancelC := context.WithTimeout(r.Context(), j.QueryTimeout)
	defer cancelC()

	_, err = j.DB.Exec(ctxC,
		`DELETE FROM users 
		WHERE id=$1`,
		userID,
	)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "User account deletion successful")
}
