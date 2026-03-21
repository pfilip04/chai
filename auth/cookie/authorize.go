package cookie

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/utils"
)

//
// Cookie checking for Authorization

func (c *CookieAuth) Authorize(r *http.Request) (uuid.UUID, error) {

	// Cookie extraction

	st, err := r.Cookie("session_token")

	if err != nil || st.Value == "" {

		return uuid.Nil, fmt.Errorf("Problem when pulling the session token from header: %w", err)
	}

	hashedSessionToken := utils.HashToken(st.Value)

	csrfToken := r.Header.Get("X-CSRF-Token")

	if csrfToken == "" {

		return uuid.Nil, errors.New("Problem when pulling the csrf token from the header")
	}

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	// Checking Cookie Validity in the DB and comparing CSRF Tokens

	sessionIdAndCsrf, err := repo.GetSessionIdAndCsrf(ctxA, hashedSessionToken)

	if err != nil {

		return uuid.Nil, fmt.Errorf("Problem when finding the session by session token in the db: %w", err)
	}

	if !utils.CheckToken(csrfToken, sessionIdAndCsrf.CsrfToken) {

		return uuid.Nil, errors.New("Csrf token missmatch")
	}

	return sessionIdAndCsrf.ID, nil
}

func (c *CookieAuth) AuthorizeRefresh(r *http.Request) (uuid.UUID, string, error) {

	// Cookie extraction

	rf, err := r.Cookie("refresh_token")

	if err != nil || rf.Value == "" {

		return uuid.Nil, "", fmt.Errorf("Problem when pulling the refresh token from the header: %w", err)
	}

	hashedRefreshToken := utils.HashToken(rf.Value)

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	// Checking Cookie Validity in the DB and comparing Refresh Tokens

	sessionID, err := repo.GetSessionIdByRefresh(ctxA, hashedRefreshToken)

	if err != nil {

		return uuid.Nil, "", fmt.Errorf("Problem when finding the session by refresh token in the db: %w", err)
	}

	return sessionID, hashedRefreshToken, nil
}

//
// Temporary MFA Cookie checking for MFA action Authorization

func (c *CookieAuth) MfaAuthorize(r *http.Request) (uuid.UUID, error) {

	// Cookie extraction

	mt, err := r.Cookie("mfa_session_token")

	if err != nil || mt.Value == "" {

		return uuid.Nil, fmt.Errorf("Problem when pulling the mfa token from header: %w", err)
	}

	hashedMfaToken := utils.HashToken(mt.Value)

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	// Checking Cookie Validity in the DB

	userID, err := repo.CheckMfaSession(ctxA, hashedMfaToken)

	if err != nil {

		return uuid.Nil, fmt.Errorf("Problem when checking the mfa token in the db: %w", err)
	}

	return userID, nil
}
