package router

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

//
// Loading the Env with godotenv

func LoadEnv(envfile string) error {

	err := godotenv.Load(envfile)

	if err != nil {
		return fmt.Errorf("Error loading the .env file: %w", err)
	}

	return nil
}

//
// Load an Env Variable into a List

func LoadEnvList(variableName string) ([]string, error) {

	origins := os.Getenv(variableName)

	if origins == "" {

		return []string{}, errors.New("Env variable can't be empty")
	}

	list := strings.Split(origins, ",")

	for i := range list {

		list[i] = strings.TrimSpace(list[i])
	}

	return list, nil
}
