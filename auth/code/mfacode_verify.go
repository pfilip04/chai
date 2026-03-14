package code

import (
	"context"

	"github.com/google/uuid"
	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
)

// Credential checking

func MfaVerify(db DbQuery, info Credentials) (uuid.UUID, bool, error) {

	ctxA, cancelA := context.WithTimeout(db.ctx, db.queryTimeout)
	defer cancelA()

	tx, err := db.Db.Begin(ctxA)

	if err != nil {

		return uuid.Nil, false, errs.DatabaseError.Err
	}

	defer tx.Rollback(ctxA)

	repo := repository.New(tx)

	// Check the Credentials

	UserAndCode, err := repo.CheckVerificationCode(ctxA, repository.CheckVerificationCodeParams{
		ID:      info.mfaId,
		MfaType: info.apiName,
	})

	if err != nil {

		return uuid.Nil, false, errs.DatabaseError.Err
	}

	if !utils.CheckToken(info.code, UserAndCode.Code) {

		return uuid.Nil, false, errs.AuthError.Err
	}

	// Clear all User Codes (if there are multiple but that shouldn't be)

	rows, err := repo.ClearMfaMail(ctxA, info.mfaId)

	if err != nil || rows == 0 {

		return uuid.Nil, false, errs.DatabaseError.Err
	}

	if err = tx.Commit(ctxA); err != nil {

		return uuid.Nil, false, errs.DatabaseError.Err
	}

	return UserAndCode.UserID, true, nil
}
