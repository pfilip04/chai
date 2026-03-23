package middlewares

import (
	"context"
	"net/http"
	"strings"

	"github.com/pfilip04/chai/global/enums"
)

func CheckForCookie(r *http.Request, name string) bool {

	c, err := r.Cookie(name)
	return err == nil && c.Value != ""
}

func CheckForJwt(r *http.Request, name string) bool {

	j := r.Header.Get(name)
	return j != ""
}

func IdentityExtractor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.URL.Path == "/web/login" || r.URL.Path == "/mobile/login" {

			if err := r.ParseForm(); err != nil {

				next.ServeHTTP(w, r)
				return
			}

			identity := r.FormValue("username_or_email")

			ctx := context.WithValue(r.Context(), enums.CtxUsernameEmail, identity)

			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		if CheckForJwt(r, "Authorization") {

			authHeader := r.Header.Get("Authorization")

			ctx := context.WithValue(r.Context(), enums.CtxJWT, strings.TrimPrefix(authHeader, "Bearer "))

			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		if CheckForCookie(r, "session_token") {

			sessionCookie, _ := r.Cookie("session_token")

			ctx := context.WithValue(r.Context(), enums.CtxSessionToken, sessionCookie.Value)

			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		if CheckForCookie(r, "mfa_session_token") {

			mfaSessionCookie, _ := r.Cookie("mfa_session_token")

			ctx := context.WithValue(r.Context(), enums.CtxMfaSessionToken, mfaSessionCookie.Value)

			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		next.ServeHTTP(w, r)
	})
}
