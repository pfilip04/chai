package router

import (
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"github.com/pfilip04/chai/global/errs"
)

//
// Loading the Env with godotenv

func LoadEnv(envfile string) error {

	err := godotenv.Load(envfile)

	if err != nil {
		return fmt.Errorf("Error loading the .env file: %v", err)
	}

	return nil
}

//
// Load an Env Variable into a List

func LoadEnvList(variableName string) ([]string, error) {

	origins := os.Getenv(variableName)

	if origins == "" {

		return []string{}, errs.LoadError.Err
	}

	list := strings.Split(origins, ",")

	for i := range list {

		list[i] = strings.TrimSpace(list[i])
	}

	return list, nil
}
