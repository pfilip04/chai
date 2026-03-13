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

	code := r.FormValue("6-DIGIT-CODE")

	mfaType := chi.URLParam(r, "mfa_type")

	id, err := uuid.Parse(r.URL.Query().Get("id"))

	if err != nil {

		http.Error(w, "Couldn't get link id", http.StatusBadRequest)
		return
	}

	userId, verified, err := MfaVerify(DbQuery{
		Db:           vc.DB,
		queryTimeout: vc.queryTimeout,
		ctx:          r.Context(),
	}, Credentials{
		mfaId:   id,
		code:    code,
		apiName: mfaType,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	if !verified {

		http.Error(w, "Verification code missmatch", http.StatusUnauthorized)
		return
	}

	mfaSessionToken, err := utils.GenerateToken(64)

	if err != nil {

		http.Error(w, errs.ServerError.Err.Error(), errs.ServerError.Status)
		return
	}

	hashedMfaToken := utils.HashToken(mfaSessionToken)
	mfaExpiresAt := time.Now().UTC().Add(vc.mfaTokenExpiration)

	ctxA, cancelA := context.WithTimeout(r.Context(), vc.queryTimeout)
	defer cancelA()

	repo := repository.New(vc.DB)

	err = repo.CreateMfaSession(ctxA, repository.CreateMfaSessionParams{
		UserID:          userId,
		MfaSessionToken: hashedMfaToken,
		ExpiresAt:       mfaExpiresAt,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

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
