package cookie

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) AdminDelete(w http.ResponseWriter, r *http.Request) {

	userId, err := uuid.Parse(r.URL.Query().Get("id"))

	if err != nil {

		errs.WriteError(w, enums.AdminDelete, err, "Cookie: Couldn't get user id from the link", errs.BadRequestError)
		return
	}

	targetAdmin, err := utils.IsAdmin(r, userId, c.DB, c.queryTimeout)

	if err != nil {

		errs.WriteError(w, enums.AdminDelete, err, "Cookie: Problem when checking target users admin status", errs.DatabaseError)
		return
	}

	if targetAdmin {

		errs.WriteError(w, enums.AdminDelete, errs.ForbiddenError.Err, "Cookie: Can't delete other admin users", errs.ForbiddenError)
		return
	}

	//
	// Deleting the target User Account from the DB

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	tx, err := c.DB.Begin(ctxA)

	if err != nil {

		errs.WriteError(w, enums.AdminDelete, err, "Cookie: Transaction start error", errs.ServerError)
		return
	}

	defer tx.Rollback(ctxA)

	repo := repository.New(tx)

	_, err = repo.ClearAllSessions(ctxA, userId)

	if err != nil {

		errs.WriteError(w, enums.AdminDelete, err, "Cookie: Problem when clearing all target user sessions", errs.DatabaseError)
		return
	}

	rows, err := repo.SoftDeleteUser(ctxA, userId)

	if err != nil {

		errs.WriteError(w, enums.AdminDelete, err, "Cookie: Problem when soft deleting the target user in the db", errs.DatabaseError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.AdminDelete, errs.DatabaseError.Err, "Cookie: No user soft deleted from the db", errs.DatabaseError)
		return
	}

	if err := tx.Commit(ctxA); err != nil {

		errs.WriteError(w, enums.AdminDelete, err, "Cookie: Transaction commit error", errs.DatabaseError)
		return
	}

	fmt.Fprintln(w, "Target user account deletion successful")
}
