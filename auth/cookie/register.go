package cookie

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/mailing"
	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) Register(w http.ResponseWriter, r *http.Request) {

	username := r.FormValue("username")
	password := r.FormValue("password")
	email := r.FormValue("email")
	mfa := r.FormValue("mfa")

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

	if !utils.CheckUniqueUsername(r, username, c.DB, c.queryTimeout) {

		http.Error(w, "Username taken", http.StatusConflict)
		return
	}

	if !utils.CheckUniqueEmail(r, email, c.DB, c.queryTimeout) {

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

	mfaBool, err := utils.ToBool(mfa)

	if err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	repo := repository.New(c.DB)

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	userId, err := repo.CreateUser(ctxA, repository.CreateUserParams{
		Username:     username,
		Email:        email,
		PasswordHash: hashedPassword,
		Mfa:          mfaBool,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	if c.sender != nil {

		code, err := utils.GenerateOTP(10, 6)

		if err != nil {

			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		codeHash := utils.HashToken(code)

		codeExpiresAt := time.Now().UTC().Add(time.Duration(c.mailingExpiration.RegExpiry))

		ctxB, cancelB := context.WithTimeout(r.Context(), c.queryTimeout)
		defer cancelB()

		mfaId, err := repo.CreateMfaMail(ctxB, repository.CreateMfaMailParams{
			UserID:    userId,
			MfaType:   enums.MfaRegVerify,
			Code:      codeHash,
			ExpiresAt: codeExpiresAt,
		})

		if err != nil {

			http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
			return
		}

		ctxC, cancelC := context.WithTimeout(r.Context(), c.queryTimeout)
		defer cancelC()

		err = mailing.Mail(ctxC, c.mailingExpiration, *c.sender, mailing.Verification{
			Id:      mfaId,
			ApiName: enums.MfaRegVerify,
			Code:    code,
		}, mailing.User{
			Username:  username,
			UserEmail: email,
		})

		if err != nil {

			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		fmt.Fprintln(w, "Registration mail sent successfully!")
	}

	fmt.Fprintln(w, "User registration successful!")
}
