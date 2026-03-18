package router

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/pfilip04/chai/config"
)

func (app *App) NewChiRouter(routercfg config.RouterConfig, cors func(http.Handler) http.Handler,
	logger func(http.Handler) http.Handler, limiter func(http.Handler) http.Handler) (chi.Router, error) {

	// Chi

	router := chi.NewRouter()

	// Base Middleware

	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)

	// Recovering and Logging

	router.Use(middleware.Recoverer)
	router.Use(logger)

	// Request Timeout and Max Request Size

	router.Use(middleware.RequestSize(routercfg.RequestSize))
	router.Use(middleware.Timeout(time.Duration(routercfg.Timeout)))

	// Rate Limiter

	router.Use(limiter)

	// Some middleware

	router.Use(middleware.NoCache)
	router.Use(middleware.SetHeader("X-Content-Type-Options", "nosniff"))
	router.Use(middleware.SetHeader("X-Frame-Options", "DENY"))

	// CORS

	router.Use(cors)

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

			r.Post("/register", app.Cookie.RegisterMfa)
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
