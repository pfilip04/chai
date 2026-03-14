package utils

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

//
// Claims for JWT

type CustomClaims struct {
	SessionID string `json:"sid"`
	jwt.RegisteredClaims
}

//
// Create JWT Token with Claims

func CreateJWT(secret []byte, userID uuid.UUID, sessionID uuid.UUID, issuer string, expiration time.Duration) (string, error) {

	now := time.Now().UTC()

	claims := CustomClaims{
		SessionID: sessionID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			Issuer:    issuer,
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiration)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(secret)
}

//
// Check JWT Token Claims

func CheckJWT(tokenString string, secret []byte, issuer string) (uuid.UUID, uuid.UUID, error) {

	errInvalid := fmt.Errorf("invalid token")

	claims := &CustomClaims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (any, error) {

			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errInvalid
			}

			return secret, nil
		},

		jwt.WithIssuer(issuer),
		jwt.WithValidMethods([]string{"HS256"}),
	)

	if err != nil || !token.Valid {
		return uuid.Nil, uuid.Nil, errInvalid
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, uuid.Nil, errInvalid
	}

	sessionID, err := uuid.Parse(claims.SessionID)
	if err != nil {
		return uuid.Nil, uuid.Nil, errInvalid
	}

	return userID, sessionID, nil
}
