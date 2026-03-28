package router

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfilip04/chai/config"
	"github.com/pfilip04/chai/global/cleanup"
	"github.com/pfilip04/chai/global/limitr"
	"github.com/pfilip04/chai/global/loggr"
	"github.com/pfilip04/chai/mailing"
)

func NewRouter(ctx context.Context, configurations string) (chi.Router, *pgxpool.Pool, error) {

	//
	// Load the config

	cfg, err := config.Load[config.Config](configurations)

	if err != nil {

		return nil, nil, fmt.Errorf("Problem when loading main config file: %w", err)
	}

	//
	// Load env

	if err := LoadEnv(cfg.EnvFile); err != nil {

		return nil, nil, fmt.Errorf("Problem when loading env file: %w", err)
	}

	//
	// Connect to DB

	dbpool, err := ConnectDB(ctx, "DATABASE_URL")

	if err != nil {

		return nil, nil, fmt.Errorf("Problem when connecting to the db: %w", err)
	}

	log.Println("Database ok")

	//
	// Loading the variables from the env

	secret := os.Getenv("SECRET_KEY")

	if secret == "" {

		return nil, nil, errors.New("secret_key isn't set")
	}

	//
	// Mailing info unpacking

	var senderinfo *mailing.Sender
	var mcfg config.MailConfig

	domain := os.Getenv("MAILING_DOMAIN")
	fdomain := os.Getenv("MAILING_FULLDOMAIN")
	name := os.Getenv("SENDER_NAME")
	apikey := os.Getenv("API_KEY")

	if cfg.MailingCfg != "" {

		senderinfo = mailing.NewSender(name, fdomain, domain, apikey)

		mcfg, err = config.Load[config.MailConfig](cfg.MailingCfg)

		if err != nil {

			return nil, nil, fmt.Errorf("Problem when loading mail config file: %w", err)
		}

	} else {

		senderinfo = nil
		mcfg = config.MailConfig{}
	}

	//
	// Handler info unpacking

	hcfg, err := config.Load[config.HandlerConfig](cfg.HandlerCfg)

	if err != nil {

		return nil, nil, fmt.Errorf("Problem when loading handler config file: %w", err)
	}

	//
	// Rate Limiting info unpacking

	rlcfg, err := config.Load[config.RateLimitConfig](cfg.RateLimitCfg)

	if err != nil {

		return nil, nil, fmt.Errorf("Problem when loading rate limiting config file: %w", err)
	}

	//
	// App init

	app := NewApp(dbpool)

	app.InitCookie(hcfg.Cookie, hcfg.MfaExp, senderinfo, mcfg)

	app.InitJWT(hcfg.JWT, hcfg.MfaExp, senderinfo, mcfg, secret)

	app.InitCode(hcfg.Code, hcfg.MfaExp)

	//
	// First Admin User

	if cfg.Admin {

		admin_username := os.Getenv("ADMIN_USERNAME")
		admin_password := os.Getenv("ADMIN_PASSWORD")
		admin_email := os.Getenv("ADMIN_EMAIL")

		message, err := InitAdminAccount(ctx, dbpool, admin_username, admin_email, admin_password)

		if err != nil {

			return nil, nil, fmt.Errorf("Problem when creating the initial admin user: %w", err)
		}

		log.Println(message)
	}

	//
	// Global Cors, Logger and Rate Limiter instances

	// Cors

	c, err := NewCors(cfg.EnvFile)

	if err != nil {

		return nil, nil, fmt.Errorf("Problem when loading cors from env file: %w", err)
	}

	cors := c.Handler

	// Logger

	logger := loggr.SlogMiddleware(loggr.NewLogger(slog.LevelInfo))

	// Limiter

	l := limitr.NewRateLimiter(rlcfg, dbpool, []byte(secret), hcfg.JWT.SpecialName)
	limiter := l.InitRateLimiter()

	//
	// Router init

	router := app.NewChiRouter(hcfg.Router, cors, logger, limiter)

	// Global Cleanup

	go cleanup.GlobalCleanup(ctx, dbpool)

	return router, dbpool, nil
}
