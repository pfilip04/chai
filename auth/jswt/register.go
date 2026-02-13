package jswt

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pfilip04/chai/utils"
)

func (j *JWTAuth) Register(w http.ResponseWriter, r *http.Request) {

	username := r.FormValue("username")
	password := r.FormValue("password")
	email := r.FormValue("email")

	//
	// Username, password and email criteria check

	if !utils.IsValidUsername(username) {

		http.Error(w, "Invalid username", http.StatusNotAcceptable)
		return
	}

	if !utils.IsValidPassword(password) {

		http.Error(w, "Invalid password", http.StatusNotAcceptable)
		return
	}

	if !utils.IsValidEmail(email) {

		http.Error(w, "Invalida e-mail", http.StatusNotAcceptable)
		return
	}

	if !j.CheckUniqueUsername(r, username) {

		http.Error(w, "Username taken", http.StatusConflict)
		return
	}

	if !j.CheckUniqueEmail(r, email) {

		http.Error(w, "E-mail taken", http.StatusConflict)
		return
	}

	//
	// Password hashing and adding the user to the database

	hashedPassword, err := utils.HashPassword(password)

	if err != nil {

		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	ctxA, cancelA := context.WithTimeout(r.Context(), j.QueryTimeout)
	defer cancelA()

	_, err = j.DB.Exec(ctxA,
		`INSERT INTO users (username, email, password_hash) 
		VALUES ($1, $2, $3)`,
		username,
		email,
		hashedPassword,
	)

	if err != nil {

		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "User registration successful!")
}
