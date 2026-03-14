package router

import (
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/pfilip04/chai/config"
)

func (app *App) NewChiRouter(routercfg config.RouterConfig, envFile string) (chi.Router, error) {

	// Chi

	router := chi.NewRouter()

	// A good base middleware stack

	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	// Set a timeout value on the request context (ctx), that will signal
	// through ctx.Done() that the request has timed out and further
	// processing should be stopped.

	router.Use(middleware.Timeout(time.Duration(routercfg.Timeout)))

	router.Use(middleware.RequestSize(routercfg.RequestSize))

	// CORS

	cors, err := NewCors(envFile)

	if err != nil {

		return nil, err
	}

	router.Use(cors.Handler)

	//
	// Api URLs

	// Web Apis

	router.Route("/web", func(r chi.Router) {

		r.Post("/register", app.Cookie.Register)

		r.Post("/login", app.Cookie.Login)
		r.Post("/logout", app.Cookie.Logout)

		r.Delete("/delete", app.Cookie.Delete)

		r.Post("/refresh", app.Cookie.Refresh)

		r.Post("/change-password", app.Cookie.ChangePassword)
		r.Post("/forgot-password", app.Cookie.ForgotPassword)

		// Mfa Apis

		r.Route("/mfa", func(r chi.Router) {

			r.Post("/login", app.Cookie.LoginMfa)
			r.Post("/password-reset", app.Cookie.PasswordReset)
		})
	})

	// Mobile Apis

	router.Route("/mobile", func(r chi.Router) {

		r.Post("/register", app.JWT.Register)

		r.Post("/login", app.JWT.Login)
		r.Post("/logout", app.JWT.Logout)

		r.Delete("/delete", app.JWT.Delete)

		r.Post("/refresh", app.JWT.Refresh)

		r.Post("/change-password", app.JWT.ChangePassword)
		r.Post("/forgot-password", app.JWT.ForgotPassword)
	})

	// Code Api

	router.Post("/code/{mfa_type}", app.Code.VerifyCode)

	return router, nil
}
