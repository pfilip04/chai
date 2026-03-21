package components

import (
	"fmt"
	"os"
	"strings"
)

//
// Mailing templates folder address relative to project root

var templatesFolder string = "mailing/components/templates/"

//
// Html to String with Username, Code and Link

func MailHtml(username string, code string, link string, htmlf string) (string, error) {

	htmlBytes, err := os.ReadFile(templatesFolder + htmlf)

	if err != nil {

		return "", fmt.Errorf("Failed to read HTML template: %w", err)
	}

	htmlBody := string(htmlBytes)
	htmlBody = strings.ReplaceAll(htmlBody, "{{USERNAME}}", username)
	htmlBody = strings.ReplaceAll(htmlBody, "{{CODE}}", code)
	htmlBody = strings.ReplaceAll(htmlBody, "{{LINK}}", link)

	return htmlBody, nil
}
