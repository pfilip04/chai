package utils

import (
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func CreateJWT(secret []byte, userID int, specialname string, expiration time.Duration) (string, error) {

	claims := jwt.MapClaims{
		"sub": strconv.Itoa(userID),
		"iss": specialname,
		"jti": uuid.NewString(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(expiration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(secret)
}

func CheckJWT(tokenString string, secret []byte, expectedIssuer string) (int, error) {
	errInvalid := fmt.Errorf("invalid token")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errInvalid
		}
		return secret, nil
	})
	if err != nil || !token.Valid {
		return 0, errInvalid
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, errInvalid
	}

	iss, ok := claims["iss"].(string)
	if !ok || iss != expectedIssuer {
		return 0, errInvalid
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return 0, errInvalid
	}

	userID, err := strconv.Atoi(sub)
	if err != nil {
		return 0, errInvalid
	}

	return userID, nil
}
