package cookie

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/mailing"
	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) Login(w http.ResponseWriter, r *http.Request) {

	//
	// Username and password check

	username := r.FormValue("username")
	password := r.FormValue("password")

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	user, err := repo.GetUserByIdOrUsername(ctxA, repository.GetUserByIdOrUsernameParams{
		Username: username,
		ID:       uuid.Nil,
	})

	if err != nil || !utils.CheckPasswordHash(password, user.PasswordHash) {

		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	if c.sender != nil {

		if !user.EmailVerified {

			http.Error(w, errs.AuthError.Err.Error(), http.StatusUnauthorized)
			return
		}

		if user.Mfa {

			message, err := mailing.SendMail(mailing.DbQuerying{
				Repo:         repo,
				QueryTimeout: c.queryTimeout,
				Ctx:          r.Context(),
			}, mailing.Mailc{
				MExp:    c.mailingExpiration.MfaLoginExpiry,
				MailCfg: c.mailingExpiration,
			}, mailing.User{
				UserID:    user.ID,
				Username:  username,
				UserEmail: user.Email,
			}, mailing.MfaType{
				ApiName:  enums.MfaLoginVerify,
				MailName: enums.Login,
			}, c.sender)

			if err != nil {

				http.Error(w, errs.ServerError.Err.Error(), errs.ServerError.Status)
				return
			}

			fmt.Fprintln(w, message)
			return
		}
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

	ctxE, cancelE := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelE()

	tx, err := c.DB.Begin(ctxE)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	defer tx.Rollback(ctxE)

	repo = repository.New(tx)

	sessionID, err := repo.InsertCookieSession(ctxE, repository.InsertCookieSessionParams{
		UserID:       user.ID,
		SessionToken: hashedSessionToken,
		CsrfToken:    hashedCsrfToken,
		Platform:     "web",
		ExpiresAt:    refreshExpiresAt,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	err = repo.InsertRefreshToken(ctxE, repository.InsertRefreshTokenParams{
		SessionID:    sessionID,
		RefreshToken: hashedRefresh,
		ExpiresAt:    refreshExpiresAt,
	})

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(ctxE); err != nil {
		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
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
