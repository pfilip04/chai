package cookie_auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//
// Database configuration for Auth access

type AuthService struct {
	DB *pgxpool.Pool
}

// Timeout

const dbTimeout = 3 * time.Second

func (a *AuthService) Register(w http.ResponseWriter, r *http.Request) {

	//
	// Username, password and email criteria check

	username := r.FormValue("username")
	password := r.FormValue("password")
	email := r.FormValue("email")

	if !isValidUsername(username) {
		er := http.StatusNotAcceptable

		http.Error(w, "Invalid username", er)
		return
	}

	if !isValidPassword(password) {
		er := http.StatusNotAcceptable

		http.Error(w, "Invalid password", er)
		return
	}

	if !isValidEmail(email) {
		er := http.StatusNotAcceptable

		http.Error(w, "Invalida e-mail", er)
		return
	}

	//
	// Password hashing and adding the user to the database

	hashedPassword, err := hashPassword(password)

	if err != nil {
		er := http.StatusInternalServerError

		http.Error(w, "Server error", er)
		return
	}

	ctx3, cancel3 := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel3()

	_, err = a.DB.Exec(ctx3,
		`INSERT INTO users (username, email, password_hash, created_at) VALUES ($1, $2, $3, NOW())`,
		username, email, hashedPassword,
	)

	if err != nil {
		er := http.StatusConflict

		http.Error(w, "Username or e-mail taken", er)
		return
	}

	fmt.Fprintln(w, "User registration successful!")
}

func (a *AuthService) Login(w http.ResponseWriter, r *http.Request) {

	//
	// Username and password check

	username := r.FormValue("username")
	password := r.FormValue("password")

	var id int
	var passwordHash string

	ctx3a, cancel3a := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel3a()

	err := a.DB.QueryRow(ctx3a,
		`SELECT id, password_hash FROM users WHERE username=$1`,
		username,
	).Scan(&id, &passwordHash)

	if err != nil || !checkPasswordHash(password, passwordHash) {
		er := http.StatusUnauthorized

		http.Error(w, "Invalid username or password", er)
		return
	}

	//
	// Generating and assigning session, csrf tokens to the user

	sessionToken, err := generateToken(32)

	if err != nil {
		er := http.StatusInternalServerError

		http.Error(w, "Server error", er)
		return
	}

	csrfToken, err := generateToken(32)

	if err != nil {
		er := http.StatusInternalServerError

		http.Error(w, "Server error", er)
		return
	}

	hashedSessionToken := hashToken(sessionToken)
	hashedCsrfToken := hashToken(csrfToken)

	ctx3b, cancel3b := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel3b()

	_, err = a.DB.Exec(ctx3b,
		`UPDATE users SET session_token=$1, csrf_token=$2 WHERE id=$3`,
		hashedSessionToken, hashedCsrfToken, id,
	)

	if err != nil {
		er := http.StatusInternalServerError

		http.Error(w, "Server error", er)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	fmt.Fprintln(w, "User login successful!")
}

func (a *AuthService) ViewProtected(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the user authorization tokens

	if err := a.SoftAuthorize(r); err != nil {
		er := http.StatusUnauthorized
		http.Error(w, "Unauthorized", er)
		return
	}

	//
	//Finding the user through the cookie

	sessionCookie, err := r.Cookie("session_token")

	if err != nil {
		er := http.StatusUnauthorized

		http.Error(w, "Unauthorized", er)
		return
	}

	hashedSessionToken := hashToken(sessionCookie.Value)

	var username string

	ctx3, cancel3 := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel3()

	err = a.DB.QueryRow(ctx3,
		`SELECT username FROM users WHERE session_token=$1`,
		hashedSessionToken,
	).Scan(&username)

	if err != nil {
		er := http.StatusInternalServerError

		http.Error(w, "Server Error", er)
		return
	}

	fmt.Fprintf(w, "Cookie validation successful! Welcome, %v!", username)
}

func (a *AuthService) Logout(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the user authorization tokens

	if err := a.HardAuthorize(r); err != nil {
		er := http.StatusUnauthorized

		http.Error(w, "Unauthorized", er)
		return
	}

	//
	// Clearing the session and CSRF tokens in the database

	sessionCookie, err := r.Cookie("session_token")

	if err != nil {
		er := http.StatusUnauthorized

		http.Error(w, "Unauthorized", er)
		return
	}

	hashedSessionToken := hashToken(sessionCookie.Value)

	ctx3, cancel3 := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel3()

	_, err = a.DB.Exec(ctx3,
		`UPDATE users SET session_token=NULL, csrf_token=NULL WHERE session_token=$1`,
		hashedSessionToken,
	)

	if err != nil {
		er := http.StatusInternalServerError

		http.Error(w, "Server error", er)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	fmt.Fprintln(w, "User logout successful")
}

func (a *AuthService) DeleteAccount(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the user authorization tokens

	if err := a.HardAuthorize(r); err != nil {
		er := http.StatusUnauthorized

		http.Error(w, "Unauthorized", er)
		return
	}

	//
	// Deleting the account from the database based on the session cookie

	sessionCookie, err := r.Cookie("session_token")

	if err != nil {
		er := http.StatusUnauthorized

		http.Error(w, "Unauthorized", er)
		return
	}

	hashedSessionToken := hashToken(sessionCookie.Value)

	ctx3, cancel3 := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel3()

	cmd, err := a.DB.Exec(ctx3,
		`DELETE FROM users WHERE session_token = $1`,
		hashedSessionToken,
	)

	if err != nil {
		er := http.StatusInternalServerError

		http.Error(w, "Server error", er)
		return
	}

	if cmd.RowsAffected() == 0 {
		er := http.StatusUnauthorized

		http.Error(w, "Unauthorized", er)
		return
	}

	//
	// Clearing the cookies

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	fmt.Fprintln(w, "User account deletion successful")
}
