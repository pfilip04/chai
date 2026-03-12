package cookie

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/errs"
)

func (c *CookieAuth) Delete(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the user authorization tokens

	sessionID, err := c.HardAuthorize(r)

	if err != nil {

		http.Error(w, errs.AuthError.Err.Error(), http.StatusUnauthorized)
		return
	}

	//
	// Deleting the account from the database based on the sessionID

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	tx, err := c.DB.Begin(ctxA)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	defer tx.Rollback(ctxA)

	repo := repository.New(tx)

	rows, err := repo.DeleteRefreshToken(ctxA, sessionID)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	if rows == 0 {

		http.Error(w, "No refresh token found/expired", http.StatusUnauthorized)
		return
	}

	userID, err := repo.DeleteCookieSession(ctxA, sessionID)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	rows, err = repo.DeleteUser(ctxA, userID)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	if rows == 0 {

		http.Error(w, "No user found to delete", http.StatusUnauthorized)
		return
	}

	if err := tx.Commit(ctxA); err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	//
	// Clearing the cookies

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().UTC().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().UTC().Add(-time.Hour),
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Expires:  time.Now().UTC().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	fmt.Fprintln(w, "User account deletion successful")
}
