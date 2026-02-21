package cookie

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/errs"
	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) Register(w http.ResponseWriter, r *http.Request) {

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

	if !c.CheckUniqueUsername(r, username) {

		http.Error(w, "Username taken", http.StatusConflict)
		return
	}

	if !c.CheckUniqueEmail(r, email) {

		http.Error(w, "E-mail taken", http.StatusConflict)
		return
	}

	//
	// Password hashing and adding the user to the database

	hashedPassword, err := utils.HashPassword(password)

	if err != nil {

		http.Error(w, "Couldn't hash", http.StatusInternalServerError)
		return
	}

	ctxA, cancelA := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	err = repo.CreateUser(ctxA, repository.CreateUserParams{
		Username:     username,
		Email:        email,
		PasswordHash: hashedPassword,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "User registration successful!")
}
