package jswt

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/pfilip04/chai/config"
	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
)

func (j *JWTAuth) ChangePassword(w http.ResponseWriter, r *http.Request) {

	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {

		http.Error(w, errs.AuthError.Err.Error(), http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	userID, _, err := utils.CheckJWT(token, j.secret, j.issuer)

	if err != nil {

		http.Error(w, errs.AuthError.Err.Error(), http.StatusUnauthorized)
		return
	}

	password := r.FormValue("old-password")

	ctxA, cancelA := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelA()

	repo := repository.New(j.DB)

	user, err := repo.GetUserByIdOrUsername(ctxA, repository.GetUserByIdOrUsernameParams{
		Username: "",
		ID:       userID,
	})

	if err != nil || !utils.CheckPasswordHash(password, user.PasswordHash) {

		http.Error(w, errs.AuthError.Err.Error(), http.StatusUnauthorized)
		return
	}

	if j.sender != nil && user.Mfa {

		message, err := utils.SendMail(config.DbQuerying{
			Repo:         repo,
			QueryTimeout: j.queryTimeout,
			Ctx:          r.Context(),
		}, config.Mailc{
			MExp:    j.mailingExpiration.ChangePassExpiry,
			MailCfg: j.mailingExpiration,
		}, config.User{
			UserID:   user.ID,
			Username: user.Username,
			Email:    user.Email,
		}, config.MfaType{
			ApiName:  enums.MfaChangePassword,
			MailName: enums.PassChange,
		}, j.sender)

		if err != nil {

			http.Error(w, errs.ServerError.Err.Error(), errs.ServerError.Status)
			return
		}

		fmt.Fprintln(w, message)
	}
}
