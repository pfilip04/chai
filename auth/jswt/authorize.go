package jswt

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
)

func (j *JWTAuth) Authorize(r *http.Request) (uuid.UUID, uuid.UUID, error) {

	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {

		return uuid.Nil, uuid.Nil, errs.AuthError.Err
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	userID, sessionID, err := utils.CheckJWT(token, j.secret, j.issuer)

	if err != nil {

		return uuid.Nil, uuid.Nil, errs.AuthError.Err
	}

	return userID, sessionID, nil
}

func (j *JWTAuth) MfaAuthorize(r *http.Request) (uuid.UUID, error) {

	mt, err := r.Cookie("mfa_session_token")
	if err != nil || mt.Value == "" {
		return uuid.Nil, errs.AuthError.Err
	}

	hashedMfaToken := utils.HashToken(mt.Value)

	ctxA, cancelA := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelA()

	repo := repository.New(j.DB)

	userID, err := repo.CheckMfaSession(ctxA, hashedMfaToken)

	if err != nil {

		return uuid.Nil, errs.AuthError.Err
	}

	return userID, nil
}
