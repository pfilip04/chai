package router

import (
	"fmt"

	"github.com/joho/godotenv"
)

func LoadEnv(envfile string) error {

	err := godotenv.Load(envfile)
	if err != nil {
		return fmt.Errorf("Error loading the .env file: %v", err)
	}

	return nil
}
