package code

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
)

func (vc *VerificationCode) VerifyCode(w http.ResponseWriter, r *http.Request) {

	// Pulling data from the form and the link

	code := r.FormValue("code")
	mfaType := chi.URLParam(r, "mfa_type")
	id, err := uuid.Parse(r.URL.Query().Get("id"))

	if err != nil {

		http.Error(w, "Couldn't get link id", http.StatusBadRequest)
		return
	}

	// Creating a temporary MFA TOKEN for authorization of the next mfa_action

	mfaSessionToken, err := utils.GenerateToken(32)

	if err != nil {

		http.Error(w, errs.ServerError.Err.Error(), errs.ServerError.Status)
		return
	}

	hashedCode := utils.HashToken(code)
	hashedMfaToken := utils.HashToken(mfaSessionToken)
	mfaExpiresAt := time.Now().UTC().Add(vc.mfaTokenExpiration)

	ctxA, cancelA := context.WithTimeout(r.Context(), vc.queryTimeout)
	defer cancelA()

	tx, err := vc.DB.Begin(ctxA)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	defer tx.Rollback(ctxA)

	repo := repository.New(tx)

	// Check the Credentials

	userID, err := repo.ConsumeVerificationCode(ctxA, repository.ConsumeVerificationCodeParams{
		ID:      id,
		MfaType: mfaType,
		Code:    hashedCode,
	})

	if err != nil {

		http.Error(w, errs.AuthError.Err.Error(), errs.AuthError.Status)
		return
	}

	// Inserting the Token into the DB

	err = repo.CreateMfaSession(ctxA, repository.CreateMfaSessionParams{
		UserID:          userID,
		MfaSessionToken: hashedMfaToken,
		ExpiresAt:       mfaExpiresAt,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	if err = tx.Commit(ctxA); err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	// Setting the token in the browser

	http.SetCookie(w, &http.Cookie{
		Name:     "mfa_session_token",
		Value:    mfaSessionToken,
		Expires:  mfaExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	fmt.Fprintln(w, "Code verification successful")
}
