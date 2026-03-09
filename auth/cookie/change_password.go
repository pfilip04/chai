package cookie

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/mailing"
	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) ChangePassword(w http.ResponseWriter, r *http.Request) {

	sessionID, err := c.HardAuthorize(r)

	if err != nil {

		http.Error(w, errs.AuthError.Error(), http.StatusUnauthorized)
		return
	}

	password := r.FormValue("old-password")

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	tx, err := c.DB.Begin(ctxA)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	defer tx.Rollback(ctxA)

	repo := repository.New(tx)

	userID, err := repo.GetUserIdBySessionId(ctxA, sessionID)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	user, err := repo.GetUsernameEmailPasswordMfaById(ctxA, userID)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(ctxA); err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	if !utils.CheckPasswordHash(password, user.PasswordHash) {

		http.Error(w, errs.AuthError.Error(), http.StatusUnauthorized)
		return
	}

	if c.sender != nil && user.Mfa {

		code, err := utils.GenerateOTP(10, 6)

		if err != nil {

			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		codeHash := utils.HashToken(code)

		codeExpiresAt := time.Now().UTC().Add(time.Duration(c.mailingExpiration.ChangePassExpiry))

		ctxB, cancelB := context.WithTimeout(r.Context(), c.queryTimeout)
		defer cancelB()

		mfaId, err := repo.CreateMfaMail(ctxB, repository.CreateMfaMailParams{
			UserID:    userID,
			MfaType:   enums.MfaChangePassword,
			Code:      codeHash,
			ExpiresAt: codeExpiresAt,
		})

		if err != nil {

			http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
			return
		}

		ctxC, cancelC := context.WithTimeout(r.Context(), c.queryTimeout)
		defer cancelC()

		err = mailing.Mail(ctxC, c.mailingExpiration, *c.sender, mailing.Verification{
			Id:      mfaId,
			ApiName: enums.MfaChangePassword,
			Code:    code,
		}, mailing.User{
			Username:  user.Username,
			UserEmail: user.Email,
		})

		if err != nil {

			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		fmt.Fprintln(w, "Password change mail sent successfully!")
	}
}
