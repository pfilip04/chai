package mailing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mailgun/mailgun-go/v4"
	"github.com/pfilip04/chai/config"
	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/mailing/components"
)

// Mailgun - 100 emais per day on a free plan

func Mail(ctx context.Context, mailCfg config.MailConfig, sender Sender, verify Verification, user User) error {

	if sender.ApiKey == "" {
		return fmt.Errorf("Apikey empty")
	}

	mg := mailgun.NewMailgun(sender.Domain, sender.ApiKey)

	//When you have an EU-domain, you must specify the endpoint:
	// mg.SetAPIBase("https://api.eu.mailgun.net")

	m := mailgun.NewMessage(sender.FromSender(), // IT NEEDS TO BE IN THIS FORM == "Name <email>"
		"VERIFICATION CODE",
		"Fallback text",
		user.ToUser(), // IT NEEDS TO BE IN THIS FORM == "username <user-email>"
	)

	link := ToLink(verify.ApiName, sender.Fulldomain, verify.Id)

	htmlf, _, err := HtmlFCase(verify.ApiName, mailCfg)

	if err != nil {

		return fmt.Errorf("Function call failed: %v", err)
	}

	htmlContent, err := components.MailHtml(user.Username, verify.Code, link, htmlf)

	if err != nil {
		return fmt.Errorf("HTML component failed: %v", err)
	}

	m.SetHTML(htmlContent)

	ctxA, cancelA := context.WithTimeout(ctx, time.Duration(mailCfg.MailTimeout))
	defer cancelA()

	_, id, err := mg.Send(ctxA, m)

	if err != nil {
		return fmt.Errorf("Email failed to send: %v", err)
	}

	fmt.Printf("Mail sent successfully, ID: %s\n", id)

	return nil
}

func HtmlFCase(name string, mailCfg config.MailConfig) (string, time.Duration, error) {

	switch name {

	case enums.MfaRegVerify:
		return "reg_verify.html", time.Duration(mailCfg.RegExpiry), nil

	case enums.MfaLoginVerify:
		return "mfa_login_verify.html", time.Duration(mailCfg.MfaLoginExpiry), nil

	case enums.MfaForgotPassword:
		return "forgot_pass_verify.html", time.Duration(mailCfg.ForgotPassExpiry), nil

	case enums.MfaChangePassword:
		return "change_pass_verify.html", time.Duration(mailCfg.ChangePassExpiry), nil

	default:
		return "", 0 * time.Second, errors.New("MailFuncApiName went wrong")
	}

}
