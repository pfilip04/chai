package cookie

import (
	"context"
	"net/http"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) LoginMfa(w http.ResponseWriter, r *http.Request) {

	//
	// Validating the MFA Authorization Token

	userId, err := c.MfaAuthorize(r)

	if err != nil {

		http.Error(w, errs.AuthError.Err.Error(), errs.AuthError.Status)
		return
	}

	//
	// Generating and Hashing Session, CSRF and Refresh Tokens

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

	//
	// Expiry times

	sessionExpiresAt := time.Now().UTC().Add(c.sessionTokenExpiration)
	refreshExpiresAt := time.Now().UTC().Add(c.refreshTokenExpiration)

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	tx, err := c.DB.Begin(ctxA)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	defer tx.Rollback(ctxA)

	repo := repository.New(tx)

	//
	// Inserting the Session into the DB

	sessionID, err := repo.InsertCookieSession(ctxA, repository.InsertCookieSessionParams{
		UserID:       userId,
		SessionToken: hashedSessionToken,
		CsrfToken:    hashedCsrfToken,
		Platform:     "web",
		ExpiresAt:    refreshExpiresAt,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	err = repo.InsertRefreshToken(ctxA, repository.InsertRefreshTokenParams{
		SessionID:    sessionID,
		RefreshToken: hashedRefresh,
		ExpiresAt:    refreshExpiresAt,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	//
	// Clearing the MFA Token in the DB

	rows, err := repo.ClearMfaSessions(ctxA, userId)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	if rows == 0 {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(ctxA); err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), errs.DatabaseError.Status)
		return
	}

	//
	// Clearing the MFA Cookie

	http.SetCookie(w, &http.Cookie{
		Name:     "mfa_session_token",
		Value:    "",
		Expires:  time.Now().UTC().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

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
		Value:    refreshToken,
		Expires:  refreshExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
}
