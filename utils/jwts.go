package utils

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func CreateJWT(secret []byte, userID uuid.UUID, sessionID uuid.UUID, specialname string, expiration time.Duration) (string, error) {

	claims := jwt.MapClaims{
		"sub": userID.String(),
		"sid": sessionID.String(),
		"iss": specialname,
		"jti": uuid.NewString(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(expiration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(secret)
}

func CheckJWT(tokenString string, secret []byte, expectedIssuer string) (uuid.UUID, uuid.UUID, error) {
	errInvalid := fmt.Errorf("invalid token")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errInvalid
		}
		return secret, nil
	})
	if err != nil || !token.Valid {
		return uuid.Nil, uuid.Nil, errInvalid
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return uuid.Nil, uuid.Nil, errInvalid
	}

	iss, ok := claims["iss"].(string)
	if !ok || iss != expectedIssuer {
		return uuid.Nil, uuid.Nil, errInvalid
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return uuid.Nil, uuid.Nil, errInvalid
	}

	userID, err := uuid.Parse(sub)

	if err != nil {
		return uuid.Nil, uuid.Nil, errInvalid
	}

	sid, ok := claims["sid"].(string)
	if !ok {
		return uuid.Nil, uuid.Nil, errInvalid
	}

	sessionID, err := uuid.Parse(sid)

	if err != nil {
		return uuid.Nil, uuid.Nil, errInvalid
	}

	return userID, sessionID, nil
}
