package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

//
// Hashing function

func HashPassword(password string) (string, error) {

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password string, hash string) bool {

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

//
// Token generation

func GenerateToken(length int) (string, error) {

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		fmt.Printf("Failed to generate token: %v", err)
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

//
// Token hashing

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func CheckToken(token string, hash string) bool {
	hashedToken := HashToken(token)
	return subtle.ConstantTimeCompare([]byte(hashedToken), []byte(hash)) == 1
}

//
// JWT generation

func CreateJWT(secret []byte, userID int, specialname string, expiration time.Duration) (string, error) {

	claims := jwt.MapClaims{
		"sub": strconv.Itoa(userID),
		"iss": specialname,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(expiration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(secret)
}
