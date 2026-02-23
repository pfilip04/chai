package components

import (
	"fmt"
	"os"
	"strings"
)

func RegisterVerify(username string, code string) (string, error) {

	htmlBytes, err := os.ReadFile("reg_verify.html")

	if err != nil {
		return "", fmt.Errorf("failed to read template: %w", err)
	}

	htmlBody := string(htmlBytes)
	htmlBody = strings.ReplaceAll(htmlBody, "{{USERNAME}}", username)
	htmlBody = strings.ReplaceAll(htmlBody, "{{CODE}}", code)

	return htmlBody, nil
}
