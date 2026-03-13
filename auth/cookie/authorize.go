package cookie

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
)

//
// Cookie checking for authorization

// Auth for POST/PATCH/PUT/DELETE...

func (c *CookieAuth) HardAuthorize(r *http.Request) (uuid.UUID, error) {

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" {
		return uuid.Nil, errs.AuthError.Err
	}

	hashedSessionToken := utils.HashToken(st.Value)

	csrfToken := r.Header.Get("X-CSRF-Token")

	if csrfToken == "" {
		return uuid.Nil, errs.AuthError.Err
	}

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	sessionIdAndCsrf, err := repo.GetSessionIdAndCsrf(ctxA, hashedSessionToken)

	if err != nil {
		return uuid.Nil, errs.AuthError.Err
	}

	if !utils.CheckToken(csrfToken, sessionIdAndCsrf.CsrfToken) {
		return uuid.Nil, errs.AuthError.Err
	}

	return sessionIdAndCsrf.ID, nil
}

// Auth for Mfa

func (c *CookieAuth) MfaAuthorize(r *http.Request) (uuid.UUID, error) {

	mt, err := r.Cookie("mfa_session_token")
	if err != nil || mt.Value == "" {
		return uuid.Nil, errs.AuthError.Err
	}

	hashedMfaToken := utils.HashToken(mt.Value)

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	userID, err := repo.CheckMfaSession(ctxA, hashedMfaToken)

	if err != nil {

		return uuid.Nil, errs.AuthError.Err
	}

	return userID, nil
}
