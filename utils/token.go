package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"

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
