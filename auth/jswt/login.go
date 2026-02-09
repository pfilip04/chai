package jswt

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pfilip04/chai/utils"
)

func (j *JWTAuth) Login(w http.ResponseWriter, r *http.Request) {

	//
	// Username and password check

	username := r.FormValue("username")
	password := r.FormValue("password")

	var id int
	var passwordHash string

	ctxA, cancelA := context.WithTimeout(r.Context(), j.QueryTimeout)
	defer cancelA()

	err := j.DB.QueryRow(ctxA,
		`SELECT id, password_hash FROM users WHERE username=$1`,
		username,
	).Scan(&id, &passwordHash)

	if err != nil || !utils.CheckPasswordHash(password, passwordHash) {
		er := http.StatusUnauthorized

		http.Error(w, "Invalid username or password", er)
		return
	}
	fmt.Fprintln(w, "User login successful!")
}
