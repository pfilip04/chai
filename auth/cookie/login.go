package cookie

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/mailing"
	"github.com/pfilip04/chai/utils"
)

func (c *CookieAuth) Login(w http.ResponseWriter, r *http.Request) {

	//
	// Extracting Form Values

	usernameOrEmail := r.FormValue("username_or_email")
	password := r.FormValue("password")

	ctxA, cancelA := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelA()

	repo := repository.New(c.DB)

	//
	// Username and password check

	user, err := repo.GetUserByUsernameOrEmail(ctxA, usernameOrEmail)

	if err != nil || !utils.CheckPasswordHash(password, user.PasswordHash) {

		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	//
	// If Mailing was specified in the JSON check if the Email is Verified and if the User opted for MFA then Send Mail

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
				Username:  user.Username,
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

	ctxE, cancelE := context.WithTimeout(r.Context(), c.queryTimeout)
	defer cancelE()

	tx, err := c.DB.Begin(ctxE)

	if err != nil {

		http.Error(w, errs.DatabaseError.Err.Error(), http.StatusInternalServerError)
		return
	}

	defer tx.Rollback(ctxE)

	repo = repository.New(tx)

	//
	// Inserting the Session into the DB

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

	fmt.Fprintln(w, "User login successful!")
}
