package cookie

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) Delete(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the user authorization tokens

	userID, err := c.HardAuthorize(r)

	if err != nil {

		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	//
	// Deleting the account from the database based on the session cookie

	sessionCookie, err := r.Cookie("session_token")

	if err != nil {

		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	hashedSessionToken := utils.HashToken(sessionCookie.Value)

	var sessionID uuid.UUID

	ctxA, cancelA := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelA()

	err = c.DB.QueryRow(ctxA,
		`DELETE FROM sessions 
		WHERE session_token=$1 
		RETURNING id`,
		hashedSessionToken,
	).Scan(&sessionID)

	if err != nil {

		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	ctxB, cancelB := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelB()

	_, err = c.DB.Exec(ctxB,
		`DELETE FROM refresh_tokens 
		WHERE session_id=$1`,
		sessionID,
	)

	if err != nil {

		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	ctxC, cancelC := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelC()

	_, err = c.DB.Exec(ctxC,
		`DELETE FROM users 
		WHERE id=$1`,
		userID,
	)

	if err != nil {

		http.Error(w, "Server error", http.StatusInternalServerError)
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
