package utils

import (
	"context"
	"fmt"
	"time"

	"github.com/pfilip04/chai/config"
	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/mailing"
)

func SendMail(db config.DbQuerying, mailc config.Mailc, user config.User, mfat config.MfaType, s *mailing.Sender) (string, error) {

	code, err := GenerateOTP(10, 6)

	if err != nil {

		return errs.ServerError.Err.Error(), errs.ServerError.Err
	}

	codeHash := HashToken(code)

	codeExpiresAt := time.Now().UTC().Add(time.Duration(mailc.MExp))

	ctx, cancel := context.WithTimeout(db.Ctx, db.QueryTimeout)
	defer cancel()

	mfaId, err := db.Repo.CreateMfaMail(ctx, repository.CreateMfaMailParams{
		UserID:    user.UserID,
		MfaType:   mfat.ApiName,
		Code:      codeHash,
		ExpiresAt: codeExpiresAt,
	})

	if err != nil {

		return errs.ServerError.Err.Error(), errs.ServerError.Err
	}

	ctxC, cancelC := context.WithTimeout(db.Ctx, db.QueryTimeout)
	defer cancelC()

	err = mailing.Mail(ctxC, mailc.MailCfg, *s, mailing.Verification{
		Id:      mfaId,
		ApiName: mfat.ApiName,
		Code:    code,
	}, mailing.User{
		Username:  user.Username,
		UserEmail: user.Email,
	})

	if err != nil {

		return errs.ServerError.Err.Error(), errs.ServerError.Err
	}

	return fmt.Sprintf("%s mail sent successfully!", mfat.MailName), nil
}
