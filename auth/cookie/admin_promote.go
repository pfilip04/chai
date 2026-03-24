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

func (c *CookieAuth) AdminPromote(w http.ResponseWriter, r *http.Request) {

	_, err := c.AdminAuthorize(r)

	if err != nil {

		errs.WriteError(w, enums.AdminPromote, err, "Cookie: Problem when authorizing admin action", errs.ForbiddenError)
		return
	}

	userId, err := uuid.Parse(r.URL.Query().Get("id"))

	if err != nil {

		errs.WriteError(w, enums.AdminPromote, err, "Cookie: Couldn't get user id from the link", errs.BadRequestError)
		return
	}

	targetAdmin, err := utils.IsAdmin(r, userId, c.DB, c.queryTimeout)

	if err != nil {

		errs.WriteError(w, enums.AdminPromote, err, "Cookie: Problem when checking target users admin status", errs.DatabaseError)
		return
	}

	if targetAdmin {

		errs.WriteError(w, enums.AdminPromote, errs.ForbiddenError.Err, "Cookie: Can't promote an already admin user", errs.ForbiddenError)
		return
	}

	//
	// Deleting the other User Account from the DB

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	rows, err := repo.PromoteSuperuser(ctxA, userId)

	if err != nil {

		errs.WriteError(w, enums.AdminPromote, err, "Cookie: Problem when promoting the target user in the db", errs.DatabaseError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.AdminPromote, errs.DatabaseError.Err, "Cookie: No user promoted in the db", errs.DatabaseError)
		return
	}

	fmt.Fprintln(w, "Target user account promotion successful")
}
