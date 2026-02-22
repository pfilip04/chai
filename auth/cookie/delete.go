package cookie

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/errs"
	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) Delete(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the user authorization tokens

	userID, err := c.HardAuthorize(r)

	if err != nil {

		http.Error(w, errs.AuthError.Error(), http.StatusUnauthorized)
		return
	}

	//
	// Deleting the account from the database based on the session cookie

	sessionCookie, err := r.Cookie("session_token")

	if err != nil {

		http.Error(w, errs.AuthError.Error(), http.StatusUnauthorized)
		return
	}

	hashedSessionToken := utils.HashToken(sessionCookie.Value)

	ctxA, cancelA := context.WithTimeout(r.Context(), c.QueryTimeout)
	defer cancelA()

	tx, err := c.DB.Begin(ctxA)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	defer tx.Rollback(ctxA)

	repo := repository.New(tx)

	sessionID, err := repo.DeleteCookieSession(ctxA, hashedSessionToken)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	rows, err := repo.DeleteRefreshToken(ctxA, sessionID)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	if rows == 0 {

		http.Error(w, "No refresh token found/expired", http.StatusUnauthorized)
		return
	}

	rows, err = repo.DeleteUser(ctxA, userID)

	if err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
		return
	}

	if rows == 0 {

		http.Error(w, "No user found to delete", http.StatusUnauthorized)
		return
	}

	if err := tx.Commit(ctxA); err != nil {

		http.Error(w, errs.DatabaseError.Error(), http.StatusInternalServerError)
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

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	fmt.Fprintln(w, "User account deletion successful")
}
