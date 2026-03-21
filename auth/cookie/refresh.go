package cookie

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) Refresh(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the Refresh Authorization Token

	sessionID, hashedRefreshToken, err := c.AuthorizeRefresh(r)

	if err != nil {

		errs.WriteError(w, enums.Refresh, err, "Cookie: Problem when Authorizing action", errs.AuthError)
		return
	}

	//
	// Generating and Hashing Session, CSRF and Refresh Tokens

	sessionToken, err := utils.GenerateToken(32)

	if err != nil {

		errs.WriteError(w, enums.Refresh, err, "Cookie: Couldn't generate session token", errs.ServerError)
		return
	}

	csrfToken, err := utils.GenerateToken(32)

	if err != nil {

		errs.WriteError(w, enums.Refresh, err, "Cookie: Couldn't generate csrf token", errs.ServerError)
		return
	}

	newRefreshToken, err := utils.GenerateToken(64)

	if err != nil {

		errs.WriteError(w, enums.Refresh, err, "Cookie: Couldn't generate refresh token", errs.ServerError)
		return
	}

	hashedSessionToken := utils.HashToken(sessionToken)
	hashedCsrfToken := utils.HashToken(csrfToken)
	hashedNewRefresh := utils.HashToken(newRefreshToken)

	//
	// Expiry times

	sessionExpiresAt := time.Now().UTC().Add(c.sessionTokenExpiration)
	refreshExpiresAt := time.Now().UTC().Add(c.refreshTokenExpiration)

	ctxB, cancelB := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelB()

	tx, err := c.DB.Begin(ctxB)

	if err != nil {

		errs.WriteError(w, enums.Refresh, err, "Cookie: Transaction start error", errs.ServerError)
		return
	}

	defer tx.Rollback(ctxB)

	repo := repository.New(tx)

	//
	// Updating the Session into the DB

	rows, err := repo.UpdateCookieSession(ctxB, repository.UpdateCookieSessionParams{
		SessionToken: hashedSessionToken,
		CsrfToken:    hashedCsrfToken,
		ExpiresAt:    refreshExpiresAt,
		ID:           sessionID,
	})

	if err != nil {

		errs.WriteError(w, enums.Refresh, err, "Cookie: Couldn't update the session in the db", errs.AuthError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.Refresh, errs.DatabaseError.Err, "Cookie: No session is updated", errs.DatabaseError)
		return
	}

	rows, err = repo.UpdateRefreshToken(ctxB, repository.UpdateRefreshTokenParams{
		RefreshToken:   hashedNewRefresh,
		ExpiresAt:      refreshExpiresAt,
		RefreshToken_2: hashedRefreshToken,
		SessionID:      sessionID,
	})

	if err != nil {

		errs.WriteError(w, enums.Refresh, err, "Cookie: Couldn't update the refresh in the db", errs.AuthError)
		return
	}

	if rows == 0 {

		errs.WriteError(w, enums.Refresh, errs.DatabaseError.Err, "Cookie: No refresh is updated", errs.DatabaseError)
		return
	}

	if err := tx.Commit(ctxB); err != nil {

		errs.WriteError(w, enums.Refresh, err, "Cookie: Transaction commit error", errs.DatabaseError)
		return
	}

	//
	// Setting the Cookies

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
