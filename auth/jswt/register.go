package jswt

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

func (j *JWTAuth) Register(w http.ResponseWriter, r *http.Request) {

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

		errs.WriteError(w, enums.Register, errs.NotAcceptableError.Err, "JWT: Invalid username", errs.NotAcceptableError)
		return
	}

	if !utils.IsValidPassword(password) {

		errs.WriteError(w, enums.Register, errs.NotAcceptableError.Err, "JWT: Invalid password", errs.NotAcceptableError)
		return
	}

	if !utils.IsValidEmail(email) {

		errs.WriteError(w, enums.Register, errs.NotAcceptableError.Err, "JWT: Invalid email", errs.NotAcceptableError)
		return
	}

	if !utils.CheckUniqueUsername(r, username, j.DB, j.queryTimeout) {

		errs.WriteError(w, enums.Register, errs.ConflictError.Err, "JWT: Username uniqueness conflict", errs.ConflictError)
		return
	}

	if !utils.CheckUniqueEmail(r, email, j.DB, j.queryTimeout) {

		errs.WriteError(w, enums.Register, errs.ConflictError.Err, "JWT: Email uniqueness conflict", errs.ConflictError)
		return
	}

	if password != password_repeat {

		errs.WriteError(w, enums.Register, errs.ConflictError.Err, "JWT: Password missmatch", errs.ConflictError)
		return
	}

	//
	// Password hashing and MFA checkbox parsing

	hashedPassword, err := utils.HashPassword(password)

	if err != nil {

		errs.WriteError(w, enums.Register, err, "JWT: Could't hash password", errs.ServerError)
		return
	}

	mfaBool, err := utils.ToBool(mfa)

	if err != nil {

		errs.WriteError(w, enums.Register, err, "JWT: Couldn't parse mfa to bool", errs.ServerError)
		return
	}

	ctxA, cancelA := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelA()

	repo := repository.New(j.DB)

	//
	// Inserting the User into the DB

	userId, err := repo.CreateUser(ctxA, repository.CreateUserParams{
		Username:     username,
		Email:        email,
		PasswordHash: hashedPassword,
		Mfa:          mfaBool,
	})

	if err != nil {

		errs.WriteError(w, enums.Register, err, "JWT: Problem when inserting the user into the db", errs.DatabaseError)
		return
	}

	//
	// If Mailing was specified in the JSON Send Mail

	if j.sender != nil {

		message, err := mailing.SendMail(mailing.DbQuerying{
			Repo:         repo,
			QueryTimeout: j.queryTimeout,
			Ctx:          r.Context(),
		}, mailing.Mailc{
			MExp:    j.mailingExpiration.RegExpiry,
			MailCfg: j.mailingExpiration,
		}, mailing.User{
			UserID:    userId,
			Username:  username,
			UserEmail: email,
		}, mailing.MfaType{
			ApiName:  enums.MfaRegVerify,
			MailName: "Register",
		}, j.sender)

		if err != nil {

			errs.WriteError(w, enums.Register, err, "JWT: Problem when sending the mail", errs.ServerError)
			return
		}

		fmt.Fprintln(w, message)
		return
	}

	fmt.Fprintln(w, "User registration successful!")
}
