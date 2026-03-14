package router

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

//
// Loading the env with godotenv

func LoadEnv(envfile string) error {

	err := godotenv.Load(envfile)

	if err != nil {
		return fmt.Errorf("Error loading the .env file: %v", err)
	}

	return nil
}

//
// Getting the Mailing Sender info from the env function

func GetEnvSenderInfo() (string, string, string, string) {

	domain := os.Getenv("MAILING_DOMAIN")

	fulldomain := os.Getenv("MAILING_FULLDOMAIN")

	senderName := os.Getenv("SENDER_NAME")

	apikey := os.Getenv("API_KEY")

	return senderName, fulldomain, domain, apikey
}
