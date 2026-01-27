package auth

import (
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

//
// User entity from the table

type User struct {
	ID           int
	Username     string
	PasswordHash string
	SessionToken string
	CSRFToken    string
	CreatedAt    time.Time
}

func (a *AuthService) Register(w http.ResponseWriter, r *http.Request) {

	//
	// Method check

	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed

		http.Error(w, "Invalid request method", er)
		return
	}

	//
	// Username and password criteria check

	username := r.FormValue("username")
	password := r.FormValue("password")
	if len(username) < 8 || len(password) < 8 {
		er := http.StatusNotAcceptable

		http.Error(w, "Invalid username/password", er)
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

	_, err = a.DB.Exec(r.Context(),
		`INSERT INTO users (username, password_hash, created_at) VALUES ($1, $2, NOW())`,
		username, hashedPassword,
	)

	if err != nil {
		er := http.StatusConflict

		http.Error(w, "Username already exists", er)
		return
	}

	fmt.Fprintln(w, "User registration successful!")
}

func (a *AuthService) Login(w http.ResponseWriter, r *http.Request) {

	//
	// Method check

	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed

		http.Error(w, "Invalid request method", er)
		return
	}

	//
	// Username and password check

	username := r.FormValue("username")
	password := r.FormValue("password")
	var user User

	err := a.DB.QueryRow(r.Context(),
		`SELECT id, password_hash FROM users WHERE username=$1`,
		username,
	).Scan(&user.ID, &user.PasswordHash)

	if err != nil || !checkPasswordHash(password, user.PasswordHash) {
		er := http.StatusUnauthorized

		http.Error(w, "Invalid username or password", er)
		return
	}

	//
	// Generating and assigning session, csrf tokens to the user

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)
	_, err = a.DB.Exec(r.Context(),
		`UPDATE users SET session_token=$1, csrf_token=$2 WHERE id=$3`,
		sessionToken, csrfToken, user.ID,
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
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false,
		Path:     "/",
	})

	fmt.Fprintln(w, "User login successful!")
}

func (a *AuthService) Protected(w http.ResponseWriter, r *http.Request) {

	//
	// Method check

	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid request method", er)
		return
	}

	//
	// Validating the user authorization tokens

	if err := a.Authorize(r); err != nil {
		er := http.StatusUnauthorized
		http.Error(w, "Unauthorized", er)
		return
	}

	username := r.FormValue("username")
	fmt.Fprintf(w, "CSRF validation successful! Welcome, %v!", username)
}

func (a *AuthService) Logout(w http.ResponseWriter, r *http.Request) {

	//
	// Method check

	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed

		http.Error(w, "Invalid request method", er)
		return
	}

	//
	// Validating the user authorization tokens

	if err := a.Authorize(r); err != nil {
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

	_, err = a.DB.Exec(r.Context(),
		`UPDATE users SET session_token=NULL, csrf_token=NULL WHERE session_token=$1`,
		sessionCookie.Value,
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
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
		Path:     "/",
	})

	fmt.Fprintln(w, "User logout successful")
}

func (a *AuthService) DeleteAccount(w http.ResponseWriter, r *http.Request) {

	//
	// Method check

	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed

		http.Error(w, "Invalid request method", er)
		return
	}

	//
	// Validating the user authorization tokens

	if err := a.Authorize(r); err != nil {
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

	cmd, err := a.DB.Exec(r.Context(),
		`DELETE FROM users WHERE session_token = $1`,
		sessionCookie.Value,
	)

	if err != nil {
		er := http.StatusInternalServerError

		http.Error(w, "Server error", er)
		return
	}

	if cmd.RowsAffected() == 0 {
		er := http.StatusUnauthorized

		http.Error(w, "User not found", er)
		return
	}

	//
	// Clearing the cookies

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
		Path:     "/",
	})

	fmt.Fprintln(w, "User account deletion successful")
}
