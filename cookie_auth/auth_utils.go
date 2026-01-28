package cookie_auth

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"net/mail"

	"golang.org/x/crypto/bcrypt"
)

//
//Method check

func checkMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		er := http.StatusMethodNotAllowed

		http.Error(w, "Invalid request Method", er)
		return false
	}

	return true
}

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

//
// Password checking

func checkPasswordHash(password string, hash string) bool {

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

//
// Token generation

func generateToken(length int) string {

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)
}
