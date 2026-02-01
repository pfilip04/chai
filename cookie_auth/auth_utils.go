package cookie_auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/mail"

	"golang.org/x/crypto/bcrypt"
)

//
//Username feng-shui

func isValidUsername(username string) bool {

	if len(username) < 3 || len(username) > 15 {
		return false
	}

	firstChar := username[0]
	lastChar := username[len(username)-1]
	if firstChar == '.' || firstChar == '_' || lastChar == '.' || lastChar == '_' {
		return false
	}

	previousChar := rune(0)
	for _, char := range username {

		if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '_' || char == '.') {
			return false
		}

		if char == '.' && previousChar == char {
			return false
		}

		previousChar = char
	}

	return true
}

//
//Password feng-shui

func isValidPassword(password string) bool {

	if len(password) < 8 || len(password) > 32 {
		return false
	}

	isDigit := false
	isUpper := false
	for _, char := range password {

		if char < 33 || char > 126 {
			return false
		}

		if char >= '0' && char <= '9' {
			isDigit = true
		}

		if char >= 'A' && char <= 'Z' {
			isUpper = true
		}
	}

	return isDigit && isUpper
}

//
//Email check

func isValidEmail(email string) bool {

	_, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}

	return true
}

//
// Hashing function

func hashPassword(password string) (string, error) {

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password string, hash string) bool {

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

//
// Token generation

func generateToken(length int) (string, error) {

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		fmt.Printf("Failed to generate token: %v", err)
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

//
// Token hashing

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func checkToken(token string, hash string) bool {
	hashedToken := hashToken(token)
	return subtle.ConstantTimeCompare([]byte(hashedToken), []byte(hash)) == 1
}
