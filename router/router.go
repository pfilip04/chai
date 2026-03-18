package router

import (
	"context"
	"errors"
	"log"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfilip04/chai/config"
	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/mailing"
)

func NewRouter(ctx context.Context, configurations string) (chi.Router, *pgxpool.Pool, error) {

	//
	// Load the config

	cfg, err := config.Load[config.Config](configurations)

	if err != nil {

		return nil, nil, errs.LoadError.Err
	}

	//
	// Load env

	if err := LoadEnv(cfg.EnvFile); err != nil {

		return nil, nil, errs.LoadError.Err
	}

	//
	// Connect to DB

	dbpool, err := ConnectDB(ctx, "DATABASE_URL")

	if err != nil {

		return nil, nil, err
	}

	log.Println("Database ok")

	//
	// Loading the variables from the env

	secret := os.Getenv("SECRET_KEY")

	if secret == "" {

		return nil, nil, errors.New("SECRET_KEY IS NOT SET")
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

			return nil, nil, errs.LoadError.Err
		}

	} else {

		senderinfo = nil
		mcfg = config.MailConfig{}
	}

	//
	// Handler info unpacking

	hcfg, err := config.Load[config.HandlerConfig](cfg.HandlerCfg)

	if err != nil {

		return nil, nil, errs.LoadError.Err
	}

	//
	// Rate Limiting info unpacking

	rlcfg, err := config.Load[config.RateLimitConfig](cfg.RateLimitCfg)

	if err != nil {

		return nil, nil, errs.LoadError.Err
	}

	//
	// App init

	app := NewApp(dbpool)

	app.InitCookie(hcfg.Cookie, hcfg.MfaExp, senderinfo, mcfg)

	app.InitJWT(hcfg.JWT, hcfg.MfaExp, senderinfo, mcfg, secret)

	app.InitCode(hcfg.Code, hcfg.MfaExp)

	//
	// Global Cors, Logger and Rate Limiter instances

	// Cors

	cors, err := NewCors(cfg.EnvFile)

	if err != nil {

		return nil, nil, err
	}

	// Logger

	logger := SlogMiddleware(NewLogger())

	// Limiter

	limiter := NewRateLimiter(rlcfg.Rps, rlcfg.Burst)

	//
	// Router init

	router, err := app.NewChiRouter(hcfg.Router, cors.Handler, logger, limiter)

	return router, dbpool, nil
}
