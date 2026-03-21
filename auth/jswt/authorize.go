package jswt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/utils"
)

//
// JWT checking for Authorization

func (j *JWTAuth) Authorize(r *http.Request) (uuid.UUID, uuid.UUID, error) {

	// JWT extraction

	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {

		return uuid.Nil, uuid.Nil, errors.New("No jwt token set")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	// JWT Claims checking

	userID, sessionID, err := utils.CheckJWT(token, j.secret, j.issuer)

	if err != nil {

		return uuid.Nil, uuid.Nil, fmt.Errorf("Problem with jwt claims: %w", err)
	}

	// DB Session checking

	ctxA, cancelA := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelA()

	repo := repository.New(j.DB)

	dbUserId, err := repo.GetUserIdBySessionId(ctxA, sessionID)

	if err != nil {

		return uuid.Nil, uuid.Nil, fmt.Errorf("Problem when finding the user id by session id in the db: %w", err)
	}

	if userID != dbUserId {

		return uuid.Nil, uuid.Nil, errors.New("User id missmatch")
	}

	return userID, sessionID, nil
}

func (j *JWTAuth) AuthorizeRefresh(r *http.Request) (uuid.UUID, uuid.UUID, string, error) {

	// JWT extraction

	rf := r.Header.Get("Refresh-Token")

	if rf == "" {

		return uuid.Nil, uuid.Nil, "", errors.New("No refresh token set")
	}

	hashedRefreshToken := utils.HashToken(rf)

	ctxA, cancelA := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelA()

	repo := repository.New(j.DB)

	// DB Session checking

	sessionID, err := repo.GetSessionIdByRefresh(ctxA, hashedRefreshToken)

	if err != nil {

		return uuid.Nil, uuid.Nil, "", fmt.Errorf("Couldn't find refresh in the db: %w", err)
	}

	ctxB, cancelB := context.WithTimeout(r.Context(), j.queryTimeout)
	defer cancelB()

	//
	// Getting User ID with Session ID to generate the JWT

	userID, err := repo.GetUserIdBySessionId(ctxB, sessionID)

	if err != nil {

		return uuid.Nil, uuid.Nil, "", fmt.Errorf("Couldn't find user id in the db: %w", err)
	}

	return userID, sessionID, hashedRefreshToken, nil
}
