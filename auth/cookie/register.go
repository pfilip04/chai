package cookie

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) Register(w http.ResponseWriter, r *http.Request) {

	//
	// Username, password and email criteria check

	username := r.FormValue("username")
	password := r.FormValue("password")
	email := r.FormValue("email")

	if !utils.IsValidUsername(username) {
		er := http.StatusNotAcceptable

		http.Error(w, "Invalid username", er)
		return
	}

	if !utils.IsValidPassword(password) {
		er := http.StatusNotAcceptable

		http.Error(w, "Invalid password", er)
		return
	}

	if !utils.IsValidEmail(email) {
		er := http.StatusNotAcceptable

		http.Error(w, "Invalida e-mail", er)
		return
	}

	//
	// Password hashing and adding the user to the database

	hashedPassword, err := utils.HashPassword(password)

	if err != nil {
		er := http.StatusInternalServerError

		http.Error(w, "Server error", er)
		return
	}

	ctxA, cancelA := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelA()

	_, err = c.DB.Exec(ctxA,
		`INSERT INTO users (username, email, password_hash, created_at) VALUES ($1, $2, $3, NOW())`,
		username, email, hashedPassword,
	)

	if err != nil {
		er := http.StatusConflict

		http.Error(w, "Username or e-mail taken", er)
		return
	}

	fmt.Fprintln(w, "User registration successful!")
}
