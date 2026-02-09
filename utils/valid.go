package utils

import (
	"net/mail"
)

//
//Username feng-shui

func IsValidUsername(username string) bool {

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

func IsValidPassword(password string) bool {

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

func IsValidEmail(email string) bool {

	_, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}

	return true
}
