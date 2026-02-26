package cookie

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) Login(w http.ResponseWriter, r *http.Request) {

	//
	// Username and password check

	username := r.FormValue("username")
	password := r.FormValue("password")

	repo := repository.New(c.DB)

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	User, err := repo.GetIdAndPass(ctxA, username)

	if err != nil || !utils.CheckPasswordHash(password, User.PasswordHash) {

		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	//
	// Generating and assigning session to the user

	sessionToken, err := utils.GenerateToken(32)

	if err != nil {

		http.Error(w, "Couldn't generate session token", http.StatusInternalServerError)
		return
	}

	csrfToken, err := utils.GenerateToken(32)

	if err != nil {

		http.Error(w, "Couldn't generate csrf token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := utils.GenerateToken(64)

	if err != nil {

		http.Error(w, "Couldn't generate refresh token", http.StatusInternalServerError)
		return
	}

	hashedSessionToken := utils.HashToken(sessionToken)
	hashedCsrfToken := utils.HashToken(csrfToken)
	hashedRefresh := utils.HashToken(refreshToken)

	sessionExpiresAt := time.Now().UTC().Add(c.sessionTokenExpiration)
	refreshExpiresAt := time.Now().UTC().Add(c.refreshTokenExpiration)

	ctxB, cancelB := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelB()

	tx, err := c.DB.Begin(ctxB)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	defer tx.Rollback(ctxB)

	repo = repository.New(tx)

	sessionID, err := repo.InsertCookieSession(ctxB, repository.InsertCookieSessionParams{
		UserID:       User.ID,
		SessionToken: hashedSessionToken,
		CsrfToken:    hashedCsrfToken,
		Platform:     "web",
		ExpiresAt:    refreshExpiresAt,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	err = repo.InsertRefreshToken(ctxB, repository.InsertRefreshTokenParams{
		SessionID:    sessionID,
		RefreshToken: hashedRefresh,
		ExpiresAt:    refreshExpiresAt,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(ctxB); err != nil {
		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  sessionExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  sessionExpiresAt,
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Expires:  refreshExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	fmt.Fprintln(w, "User login successful!")
}
