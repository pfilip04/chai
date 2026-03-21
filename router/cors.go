package router

import (
	"fmt"
	"os"
	"strconv"

	"github.com/pfilip04/chai/utils"
	"github.com/rs/cors"
)

func NewCors(envFile string) (*cors.Cors, error) {

	//
	// Load Env

	if err := LoadEnv(envFile); err != nil {

		return nil, fmt.Errorf("Problem when loading env file: %w", err)
	}

	//
	// Load Env Variables

	origins, err := LoadEnvList("ALLOWED_ORIGINS")

	if err != nil {

		return nil, fmt.Errorf("Problem when loading allowed_origins: %w", err)
	}

	methods, err := LoadEnvList("ALLOWED_METHODS")

	if err != nil {

		return nil, fmt.Errorf("Problem when loading allowed_methods: %w", err)
	}

	headers, err := LoadEnvList("ALLOWED_HEADERS")

	if err != nil {

		return nil, fmt.Errorf("Problem when loading allowed_headers: %w", err)
	}

	credentials, err := utils.ToBool(os.Getenv("ALLOWED_CREDENTIALS"))

	if err != nil {

		return nil, fmt.Errorf("Problem when loading allowed_credentials: %w", err)
	}

	maxAge, err := strconv.Atoi(os.Getenv("MAX_AGE"))

	if err != nil {

		return nil, fmt.Errorf("Problem when loading max_age: %w", err)
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
