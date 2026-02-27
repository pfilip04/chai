package code

import (
	"context"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
)

func MfaVerify(db DbQuery, info Credentials) (bool, error) {

	ctxA, cancelA := context.WithTimeout(db.ctx, db.queryTimeout)
	defer cancelA()

	tx, err := db.Db.Begin(ctxA)

	if err != nil {

		return false, errs.DatabaseError
	}

	defer tx.Rollback(ctxA)

	repo := repository.New(tx)

	dbCode, err := repo.CheckVerificationCode(ctxA, repository.CheckVerificationCodeParams{
		ID:      info.mfaId,
		MfaType: info.apiName,
	})

	if err != nil {

		return false, errs.DatabaseError
	}

	if !utils.CheckToken(info.code, dbCode) {

		return false, nil
	}

	rows, err := repo.ClearMfaMail(ctxA, info.mfaId)

	if err != nil {

		return false, errs.DatabaseError
	}

	if rows == 0 {

		return false, errs.DatabaseError
	}

	if err = tx.Commit(ctxA); err != nil {

		return false, errs.DatabaseError
	}

	return true, nil
}
