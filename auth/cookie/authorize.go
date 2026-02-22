package cookie

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/errs"
	"github.com/pfilip04/chai/utils"
)

//
// Cookie checking for authorization

// Auth for GET

func (c *CookieAuth) SoftAuthorize(r *http.Request) (uuid.UUID, error) {

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" {
		return uuid.Nil, errs.AuthError
	}

	hashedSessionToken := utils.HashToken(st.Value)

	ctxA, cancelA := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	IdAndCsrf, err := repo.GetUserIdAndCsrfToken(ctxA, hashedSessionToken)

	if err != nil {
		return uuid.Nil, errs.AuthError
	}

	return IdAndCsrf.UserID, nil
}

// Auth for POST/PATCH/PUT/DELETE...

func (c *CookieAuth) HardAuthorize(r *http.Request) (uuid.UUID, error) {

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" {
		return uuid.Nil, errs.AuthError
	}

	hashedSessionToken := utils.HashToken(st.Value)

	csrfToken := r.Header.Get("X-CSRF-Token")

	if csrfToken == "" {
		return uuid.Nil, errs.AuthError
	}

	ctxA, cancelA := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	IdAndCsrf, err := repo.GetUserIdAndCsrfToken(ctxA, hashedSessionToken)

	if err != nil {
		return uuid.Nil, errs.AuthError
	}

	if !utils.CheckToken(csrfToken, IdAndCsrf.CsrfToken) {
		return uuid.Nil, errs.AuthError
	}

	return IdAndCsrf.UserID, nil
}
