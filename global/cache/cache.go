package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/utils"
)

func NewCache(secret []byte, issuer string) *Cache {

	cache := &Cache{
		j_info:    NewSpecialInfo(secret, issuer),
		lookupMap: make(map[string]Identity),
	}

	go cache.cacheCleanup()

	return cache
}

var cacheData = []string{
	enums.CtxJWT,
	enums.CtxUsernameEmail,
	enums.CtxSessionToken,
	enums.CtxJWTRefreshToken,
	enums.CtxCookieRefreshToken,
	enums.CtxMfaSessionToken,
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

func (ch *Cache) AddIntoLookup(key string, id uuid.UUID, usernameEmail bool) {

	exp := 30 * time.Minute

	if usernameEmail {

		exp = time.Hour
	}

	ch.mu.Lock()

	ch.lookupMap[key] = Identity{
		UserID:    id,
		ExpiresAt: time.Now().UTC().Add(exp),
	}

	ch.mu.Unlock()
}

func (ch *Cache) GetCache(ctx context.Context) (uuid.UUID, string, error) {

	for _, dataType := range cacheData {

		val := ctx.Value(dataType)

		if val != nil {

			userID, miss, err := ch.CheckLookup(val, dataType)

			if err != nil {

				return uuid.Nil, "", err
			}

			if miss {

				return uuid.Nil, dataType, nil
			}

			return userID, "", nil
		}
	}

	return uuid.Nil, "", errors.New("Couldn't extract from context")
}

func (ch *Cache) SetCache(ctx context.Context, db *pgxpool.Pool, timeout time.Duration, dataType string) (uuid.UUID, error) {

	val, ok := ctx.Value(dataType).(string)

	if !ok {

		return uuid.Nil, fmt.Errorf("Error with Lookup on %s: %w", dataType, errors.New("Problem when reading context data"))
	}

	ctxA, cancelA := context.WithTimeout(ctx, timeout)
	defer cancelA()

	repo := repository.New(db)

	switch dataType {

	case enums.CtxJWT:

		userID, _, err := utils.CheckJWT(val, ch.j_info.secret, ch.j_info.issuer)

		if err != nil {

			return uuid.Nil, fmt.Errorf("Problem with jwt claims: %w", err)
		}

		ch.AddIntoLookup(val, userID, false)

		return userID, nil

	case enums.CtxUsernameEmail:

		user, err := repo.GetIdentifierByUsernameOrEmail(ctxA, val)

		if err != nil {

			return uuid.Nil, fmt.Errorf("Couldn't get username/email identifier from the db: %w", err)
		}

		ch.AddIntoLookup(user.Username, user.ID, true)
		ch.AddIntoLookup(user.Email, user.ID, true)

		return user.ID, nil

	case enums.CtxSessionToken:

		userID, err := repo.GetIdentifierBySession(ctxA, utils.HashToken(val))

		if err != nil {

			return uuid.Nil, fmt.Errorf("Couldn't get session token identifier from the db: %w", err)
		}

		ch.AddIntoLookup(val, userID, false)

		return userID, nil

	case enums.CtxJWTRefreshToken, enums.CtxCookieRefreshToken:

		userID, err := repo.GetIdentifierByRefresh(ctxA, utils.HashToken(val))

		if err != nil {

			return uuid.Nil, fmt.Errorf("Couldn't get refresh token identifier from the db: %w", err)
		}

		ch.AddIntoLookup(val, userID, false)

		return userID, nil

	case enums.CtxMfaSessionToken:

		userID, err := repo.GetIdentifierByMfaSession(ctxA, utils.HashToken(val))

		if err != nil {

			return uuid.Nil, fmt.Errorf("Couldn't get mfa session token identifier from the db: %w", err)
		}

		ch.AddIntoLookup(val, userID, false)

		return userID, nil

	default:

		return uuid.Nil, errors.New("Something went wrong when checking data")
	}
}
