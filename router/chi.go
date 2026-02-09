package router

import (
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func (app *App) NewChiRouter(timeout time.Duration, reqsize int64) chi.Router {

	router := chi.NewRouter()

	// A good base middleware stack

	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	// Set a timeout value on the request context (ctx), that will signal
	// through ctx.Done() that the request has timed out and further
	// processing should be stopped.

	router.Use(middleware.Timeout(timeout))

	router.Use(middleware.RequestSize(reqsize))

	// Api URLs

	router.Route("/auth", func(r chi.Router) {
		r.Post("/register", app.CookieDB.Register)
		r.Post("/login", app.CookieDB.Login)
		r.Post("/logout", app.CookieDB.Logout)
		r.Delete("/delete", app.CookieDB.DeleteAccount)
	})

	router.Get("/protected", app.CookieDB.ViewProtected)

	return router
}
