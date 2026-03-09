package jswt

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
)

func (j *JWTAuth) Authorize(r *http.Request) (uuid.UUID, uuid.UUID, error) {

	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {

		return uuid.Nil, uuid.Nil, errs.AuthError
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	userID, sessionID, err := utils.CheckJWT(token, j.secret, j.issuer)

	if err != nil {

		return uuid.Nil, uuid.Nil, errs.AuthError
	}

	return userID, sessionID, nil
}
