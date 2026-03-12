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

func (c *CookieAuth) ForgotPassword(w http.ResponseWriter, r *http.Request) {

	usernameOrEmail := r.FormValue("username_or_email")

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	user, err := repo.FindUserByUsernameOrEmail(ctxA, usernameOrEmail)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusBadRequest)
		return
	}

	if c.sender == nil {

		http.Error(w, "Can't use this feature without mailing true in config", http.StatusConflict)
		return
	}

	message, err := utils.SendMail(config.DbQuerying{
		Repo:         repo,
		QueryTimeout: c.queryTimeout,
		Ctx:          r.Context(),
	}, config.Mailc{
		MExp:    c.mailingExpiration.ForgotPassExpiry,
		MailCfg: c.mailingExpiration,
	}, config.User{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
	}, config.MfaType{
		ApiName:  enums.MfaForgotPassword,
		MailName: enums.PassReset,
	}, c.sender)

	if err != nil {

		http.Error(w, errs.ServerError.Err.Error(), errs.ServerError.Status)
		return
	}

	fmt.Fprintln(w, message)
}
