package cookie

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pfilip04/chai/config"
	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) ChangePassword(w http.ResponseWriter, r *http.Request) {

	sessionID, err := c.HardAuthorize(r)

	if err != nil {

		http.Error(w, errs.AuthError.Err.Error(), http.StatusUnauthorized)
		return
	}

	password := r.FormValue("old-password")

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	userID, err := repo.GetUserIdBySessionId(ctxA, sessionID)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	ctxB, cancelB := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelB()

	user, err := repo.GetUserByIdOrUsername(ctxB, repository.GetUserByIdOrUsernameParams{
		Username: "",
		ID:       userID,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	if !utils.CheckPasswordHash(password, user.PasswordHash) {

		http.Error(w, errs.AuthError.Err.Error(), http.StatusUnauthorized)
		return
	}

	if c.sender != nil && user.Mfa {

		message, err := utils.SendMail(config.DbQuerying{
			Repo:         repo,
			QueryTimeout: c.queryTimeout,
			Ctx:          r.Context(),
		}, config.Mailc{
			MExp:    c.mailingExpiration.ChangePassExpiry,
			MailCfg: c.mailingExpiration,
		}, config.User{
			UserID:   user.ID,
			Username: user.Username,
			Email:    user.Email,
		}, config.MfaType{
			ApiName:  enums.MfaChangePassword,
			MailName: enums.PassChange,
		}, c.sender)

		if err != nil {

			http.Error(w, errs.ServerError.Err.Error(), errs.ServerError.Status)
			return
		}

		fmt.Fprintln(w, message)
	}
}
