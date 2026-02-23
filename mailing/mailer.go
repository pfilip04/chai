package mailing

import (
	"context"
	"fmt"
	"time"

	"github.com/mailgun/mailgun-go/v4"

	"github.com/pfilip04/chai/mailing/components"
	"github.com/pfilip04/chai/utils"
)

// Mailgun - 100 emais per day on a free plan

func mail(ctx context.Context, sender Sender, user User, apiKey string) error {

	if apiKey == "" {
		apiKey = "API_KEY"
	}

	mg := mailgun.NewMailgun(sender.Domain, apiKey)

	//When you have an EU-domain, you must specify the endpoint:
	// mg.SetAPIBase("https://api.eu.mailgun.net")

	m := mailgun.NewMessage(sender.FromSender(), // IT NEEDS TO BE IN THIS FORM == "Name <email>"
		"REGISTRATION CODE",
		"Fallback text",
		user.ToUser(), // IT NEEDS TO BE IN THIS FORM == "username <user-email>"
	)

	code, err := utils.GenerateOTP(10, 6)

	if err != nil {
		return fmt.Errorf("Code generation failed: %v", err)
	}

	htmlContent, err := components.RegisterVerify(user.Username, code)

	if err != nil {
		return fmt.Errorf("HTML component failed: %v", err)
	}

	m.SetHTML(htmlContent)

	ctxA, cancelA := context.WithTimeout(ctx, time.Second*30)
	defer cancelA()

	_, id, err := mg.Send(ctxA, m)
	fmt.Println(id)

	return err
}
