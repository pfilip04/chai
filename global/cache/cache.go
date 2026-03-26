package cache

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/pfilip04/chai/global/enums"
)

func NewCache(secret []byte, issuer string) *Cache {

	cache := &Cache{
		j_info:    NewSpecialInfo(secret, issuer),
		lookupMap: make(map[string]Identity),
	}

	return cache
}

func (ch *Cache) CheckLookup(data any, dataType string) (uuid.UUID, bool, error) {

	dataStr, ok := data.(string)

	if !ok {

		return uuid.Nil, false, fmt.Errorf("Error with Lookup on %s: %w", dataType, errors.New("Problem when reading context data"))
	}

	ch.mu.RLock()
	user, ok := ch.lookupMap[dataStr]
	ch.mu.RUnlock()

	if !ok {

		return uuid.Nil, true, nil
	}

	return user.UserID, false, nil
}

func (ch *Cache) GetCache(ctx context.Context) (uuid.UUID, string, error) {

	jwt := ctx.Value(enums.CtxJWT)

	if jwt != nil {

		userID, miss, err := ch.CheckLookup(jwt, enums.CtxJWT)

		if err != nil {

			return uuid.Nil, "", err
		}

		if miss {

			return uuid.Nil, enums.CtxJWT, nil
		}

		return userID, "", nil
	}

	usernameEmail := ctx.Value(enums.CtxUsernameEmail)

	if usernameEmail != nil {

		userID, miss, err := ch.CheckLookup(usernameEmail, enums.CtxUsernameEmail)

		if err != nil {

			return uuid.Nil, "", err
		}

		if miss {

			return uuid.Nil, enums.CtxUsernameEmail, nil
		}

		return userID, "", nil
	}

	session := ctx.Value(enums.CtxSessionToken)

	if session != nil {

		userID, miss, err := ch.CheckLookup(session, enums.CtxSessionToken)

		if err != nil {

			return uuid.Nil, "", err
		}

		if miss {

			return uuid.Nil, enums.CtxSessionToken, nil
		}

		return userID, "", nil
	}

	jwtRefresh := ctx.Value(enums.CtxJWTRefreshToken)

	if jwtRefresh != nil {

		userID, miss, err := ch.CheckLookup(jwtRefresh, enums.CtxJWTRefreshToken)

		if err != nil {

			return uuid.Nil, "", err
		}

		if miss {

			return uuid.Nil, enums.CtxJWTRefreshToken, nil
		}

		return userID, "", nil
	}

	cookieRefresh := ctx.Value(enums.CtxCookieRefreshToken)

	if cookieRefresh != nil {

		userID, miss, err := ch.CheckLookup(cookieRefresh, enums.CtxCookieRefreshToken)

		if err != nil {

			return uuid.Nil, "", err
		}

		if miss {

			return uuid.Nil, enums.CtxCookieRefreshToken, nil
		}

		return userID, "", nil
	}

	mfaSession := ctx.Value(enums.CtxMfaSessionToken)

	if mfaSession != nil {

		userID, miss, err := ch.CheckLookup(mfaSession, enums.CtxMfaSessionToken)

		if err != nil {

			return uuid.Nil, "", err
		}

		if miss {

			return uuid.Nil, enums.CtxMfaSessionToken, nil
		}

		return userID, "", nil
	}

	return uuid.Nil, "", errors.New("Couldn't extract from context")
}

func SetCache(ctx context.Context, dataType string) error {

	//
	// DB queries for finding user data and inserting into cache

	return nil
}
