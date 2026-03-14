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

//
// JWT checking for Authorization

func (j *JWTAuth) Authorize(r *http.Request) (uuid.UUID, uuid.UUID, error) {

	// JWT extraction

	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {

		return uuid.Nil, uuid.Nil, errs.AuthError.Err
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	// JWT Claims checking

	userID, sessionID, err := utils.CheckJWT(token, j.secret, j.issuer)

	if err != nil {

		return uuid.Nil, uuid.Nil, err
	}

	// DB Session checking

	ctxA, cancelA := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelA()

	repo := repository.New(j.DB)

	dbUserId, err := repo.GetUserIdBySessionId(ctxA, sessionID)

	if err != nil {

		return uuid.Nil, uuid.Nil, err
	}

	if userID != dbUserId {

		return uuid.Nil, uuid.Nil, errs.AuthError.Err
	}

	return userID, sessionID, nil
}
