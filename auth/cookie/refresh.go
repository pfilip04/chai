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

func (c *CookieAuth) Refresh(w http.ResponseWriter, r *http.Request) {

	rf, err := r.Cookie("refresh_token")

	if err != nil || rf.Value == "" {

		http.Error(w, errs.AuthError.Error(), http.StatusUnauthorized)
		return
	}

	hashedRefreshToken := utils.HashToken(rf.Value)

	sessionExpiresAt := time.Now().UTC().Add(c.sessionTokenExpiration)
	refreshExpiresAt := time.Now().UTC().Add(c.refreshTokenExpiration)

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	sessionID, err := repo.GetSessionIdByRefresh(ctxA, hashedRefreshToken)

	if err != nil {

		http.Error(w, "Couldn't find refresh", http.StatusUnauthorized)
		return
	}

	sessionToken, err := utils.GenerateToken(32)

	if err != nil {

		http.Error(w, "Could't generate session token", http.StatusInternalServerError)
		return
	}

	csrfToken, err := utils.GenerateToken(32)

	if err != nil {

		http.Error(w, "Couldn't generate csrf token", http.StatusInternalServerError)
		return
	}

	newRefreshToken, err := utils.GenerateToken(64)

	if err != nil {

		http.Error(w, "Couldn't generate refresh token", http.StatusInternalServerError)
		return
	}

	hashedSessionToken := utils.HashToken(sessionToken)
	hashedCsrfToken := utils.HashToken(csrfToken)
	hashedNewRefresh := utils.HashToken(newRefreshToken)

	ctxB, cancelB := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelB()

	tx, err := c.DB.Begin(ctxB)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	defer tx.Rollback(ctxB)

	repo = repository.New(tx)

	rows, err := repo.UpdateCookieSession(ctxB, repository.UpdateCookieSessionParams{
		SessionToken: hashedSessionToken,
		CsrfToken:    hashedCsrfToken,
		ExpiresAt:    refreshExpiresAt,
		ID:           sessionID,
	})

	if err != nil {

		http.Error(w, "Couldn't refresh tokens", http.StatusUnauthorized)
		return
	}

	if rows == 0 {
		http.Error(w, "Couldn't find session", http.StatusUnauthorized)
		return
	}

	rows, err = repo.UpdateRefreshToken(ctxB, repository.UpdateRefreshTokenParams{
		RefreshToken:   hashedNewRefresh,
		ExpiresAt:      refreshExpiresAt,
		RefreshToken_2: hashedRefreshToken,
		SessionID:      sessionID,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	if rows == 0 {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
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
		Value:    newRefreshToken,
		Expires:  refreshExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	fmt.Fprintln(w, "Refresh successful!")
}
