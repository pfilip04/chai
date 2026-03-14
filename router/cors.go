package router

import (
	"os"
	"strconv"

	"github.com/pfilip04/chai/global/errs"
	"github.com/pfilip04/chai/utils"
	"github.com/rs/cors"
)

func NewCors(envFile string) (*cors.Cors, error) {

	//
	// Load Env

	if err := LoadEnv(envFile); err != nil {

		return nil, errs.LoadError.Err
	}

	//
	// Load Env Variables

	origins, err := LoadEnvList("ALLOWED_ORIGINS")

	if err != nil {

		return nil, errs.LoadError.Err
	}

	methods, err := LoadEnvList("ALLOWED_METHODS")

	if err != nil {

		return nil, errs.LoadError.Err
	}

	headers, err := LoadEnvList("ALLOWED_HEADERS")

	if err != nil {

		return nil, errs.LoadError.Err
	}

	credentials, err := utils.ToBool(os.Getenv("ALLOWED_CREDENTIALS"))

	if err != nil {

		return nil, errs.ServerError.Err
	}

	maxAge, err := strconv.Atoi(os.Getenv("MAX_AGE"))

	if err != nil {

		return nil, errs.ServerError.Err
	}

	//
	// Cors initialization

	c := cors.New(cors.Options{

		AllowedOrigins:   origins,
		AllowedMethods:   methods,
		AllowedHeaders:   headers,
		AllowCredentials: credentials,
		MaxAge:           maxAge,
	})

	return c, nil
}
