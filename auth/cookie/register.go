package cookie

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/mailing"
	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) Register(w http.ResponseWriter, r *http.Request) {

	//
	// Extracting Form Values

	username := r.FormValue("username")
	email := r.FormValue("email")

	password := r.FormValue("password")
	password_repeat := r.FormValue("password-repeat")

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

	if password != password_repeat {

		http.Error(w, "Password missmatch", http.StatusConflict)
		return
	}

	//
	// Password hashing and MFA checkbox parsing

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

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	//
	// Inserting the User into the DB

	userId, err := repo.CreateUser(ctxA, repository.CreateUserParams{
		Username:     username,
		Email:        email,
		PasswordHash: hashedPassword,
		Mfa:          mfaBool,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	//
	// If Mailing was specified in the JSON Send Mail

	if c.sender != nil {

		message, err := mailing.SendMail(mailing.DbQuerying{
			Repo:         repo,
			QueryTimeout: c.queryTimeout,
			Ctx:          r.Context(),
		}, mailing.Mailc{
			MExp:    c.mailingExpiration.RegExpiry,
			MailCfg: c.mailingExpiration,
		}, mailing.User{
			UserID:    userId,
			Username:  username,
			UserEmail: email,
		}, mailing.MfaType{
			ApiName:  enums.MfaRegVerify,
			MailName: enums.Reg,
		}, c.sender)

		if err != nil {

			http.Error(w, errs.ServerError.Err.Error(), errs.ServerError.Status)
			return
		}

		fmt.Fprintln(w, message)
	}

	fmt.Fprintln(w, "User registration successful!")
}
