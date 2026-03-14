package mailing

import (
	"context"
	"fmt"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
)

//
// Complete Mail Sending with Code generation and DB writing

func SendMail(db DbQuerying, mailc Mailc, user User, mfat MfaType, s *Sender) (string, error) {

	//
	// Code generation and hashing, inserting it into the DB

	code, err := utils.GenerateOTP(10, 6)

	if err != nil {

		return errs.ServerError.Err.Error(), errs.ServerError.Err
	}

	codeHash := utils.HashToken(code)

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

	//
	// Mail Sending Call

	ctxC, cancelC := context.WithTimeout(db.Ctx, db.QueryTimeout)
	defer cancelC()

	err = Mail(ctxC, mailc.MailCfg, *s, Verification{
		Id:      mfaId,
		MfaType: mfat.ApiName,
		Code:    code,
	}, User{
		Username:  user.Username,
		UserEmail: user.UserEmail,
	})

	if err != nil {

		return errs.ServerError.Err.Error(), errs.ServerError.Err
	}

	return fmt.Sprintf("%s mail sent successfully!", mfat.MailName), nil
}
