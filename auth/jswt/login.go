package jswt

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/pfilip04/chai/utils"
)

func (j *JWTAuth) Login(w http.ResponseWriter, r *http.Request) {

	//
	// Username and password check

	username := r.FormValue("username")
	password := r.FormValue("password")

	var id int
	var passwordHash string

	ctxA, cancelA := context.WithTimeout(r.Context(), j.QueryTimeout)
	defer cancelA()

	err := j.DB.QueryRow(ctxA,
		`SELECT id, password_hash FROM users WHERE username=$1`,
		username,
	).Scan(&id, &passwordHash)

	if err != nil || !utils.CheckPasswordHash(password, passwordHash) {
		er := http.StatusUnauthorized

		http.Error(w, "Invalid username or password", er)
		return
	}

	tokenString, err := utils.CreateJWT(j.secret, id, j.specialname, j.expiration)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Authorization", "Bearer "+tokenString)

	resp := struct {
		Token string `json:"token"`
	}{
		Token: tokenString,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}
