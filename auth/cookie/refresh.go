package cookie

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) Refresh(w http.ResponseWriter, r *http.Request) {

	rf, err := r.Cookie("refresh_token")
	if err != nil || rf.Value == "" {

		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	hashedRefreshToken := utils.HashToken(rf.Value)

	var sessionID uuid.UUID
	var userID uuid.UUID
	expiresAt := time.Now().Add(24 * time.Hour)

	ctxA, cancelA := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelA()

	err = c.DB.QueryRow(ctxA,
		`SELECT session_id FROM refresh_tokens 
		WHERE refresh_token=$1 AND expires_at > NOW()`,
		hashedRefreshToken,
	).Scan(&sessionID)

	if err != nil {

		http.Error(w, "Cant find refresh", http.StatusUnauthorized)
		return
	}

	ctxB, cancelB := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelB()

	err = c.DB.QueryRow(ctxB,
		`SELECT user_id FROM sessions 
		WHERE id=$1`,
		sessionID,
	).Scan(&userID)

	if err != nil {

		http.Error(w, "Can't find userID", http.StatusUnauthorized)
		return
	}

	sessionToken, err := utils.GenerateToken(32)

	if err != nil {

		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	csrfToken, err := utils.GenerateToken(32)

	if err != nil {

		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	hashedSessionToken := utils.HashToken(sessionToken)
	hashedCsrfToken := utils.HashToken(csrfToken)

	ctxC, cancelC := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelC()

	_, err = c.DB.Exec(ctxC,
		`UPDATE sessions 
		SET session_token=$1, csrf_token=$2, expires_at=$3 
		WHERE id=$4`,
		hashedSessionToken,
		hashedCsrfToken,
		expiresAt,
		sessionID,
	)

	if err != nil {

		http.Error(w, "Can't refresh tokens", http.StatusUnauthorized)
		return
	}

	newRefreshToken, err := utils.GenerateToken(64)

	if err != nil {

		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	hashedNewRefresh := utils.HashToken(newRefreshToken)

	ctxD, cancelD := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelD()

	_, err = c.DB.Exec(ctxD,
		`UPDATE refresh_tokens 
		SET refresh_token=$1, expires_at=$2 
		WHERE refresh_token=$3 AND session_id=$4`,
		hashedNewRefresh,
		expiresAt,
		hashedRefreshToken,
		sessionID,
	)

	if err != nil {

		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  expiresAt,
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    newRefreshToken,
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	fmt.Fprintln(w, "Refresh successful!")
}
