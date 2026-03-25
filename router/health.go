package router

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
)

func (a *App) Live(w http.ResponseWriter, r *http.Request) {

	w.WriteHeader(http.StatusOK)
	fmt.Println("App is live")
}

func (a *App) Ready(w http.ResponseWriter, r *http.Request) {

	ctx5, cancel5 := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel5()

	err := a.DB.Ping(ctx5)

	if err != nil {

		errs.WriteError(w, enums.HealthLive, err, "Health: Database unreachable", errs.ServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Println("Database is ready")
}

func (a *App) Startup(w http.ResponseWriter, r *http.Request) {

	ctx5, cancel5 := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel5()

	var migration struct {
		Version int64
		Dirty   bool
	}

	err := a.DB.QueryRow(ctx5, `
		SELECT version, dirty
		FROM schema_migrations
	`).Scan(&migration.Version, &migration.Dirty)

	if err != nil {

		errs.WriteError(w, enums.HealthStartup, err, "Health: Couldn't get migration info", errs.DatabaseError)
		return
	}

	if migration.Dirty {

		errs.WriteError(w, enums.HealthStartup, errs.DatabaseError.Err, "Health: Dirty migration", errs.DatabaseError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Printf("Migration okay. Version: %d", migration.Version)
	fmt.Println()
}
