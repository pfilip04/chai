package auth

import (
	"crypto/rand"
	"encoding/base64"
	"log"

	"golang.org/x/crypto/bcrypt"
)

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
