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

//
// Mailgun - 100 emais per day on a free plan

func Mail(ctx context.Context, mailCfg config.MailConfig, sender Sender, verify Verification, user User) error {

	if sender.ApiKey == "" {

		return errors.New("Apikey Empty!")
	}

	//
	// Mailgun

	mg := mailgun.NewMailgun(sender.Domain, sender.ApiKey)

	// When you have an EU-domain, you must specify the endpoint:
	// mg.SetAPIBase("https://api.eu.mailgun.net")

	// Mailgun message

	m := mailgun.NewMessage(sender.FromSender(), // IT NEEDS TO BE IN THIS FORM == "Name <email>"
		"VERIFICATION CODE",
		"Fallback text",
		user.ToUser(), // IT NEEDS TO BE IN THIS FORM == "username <user-email>"
	)

	// Link Creation

	link := ToLink(verify.MfaType, sender.Fulldomain, verify.Id)

	// Choosing the Html file for mfa_type case

	htmlf, _, err := HtmlFCase(verify.MfaType, mailCfg)

	if err != nil {

		return err
	}

	// Mail String content Setting

	htmlContent, err := components.MailHtml(user.Username, verify.Code, link, htmlf)

	if err != nil {

		return err
	}

	m.SetHTML(htmlContent)

	//
	// Sending the Mail

	ctxA, cancelA := context.WithTimeout(ctx, time.Duration(mailCfg.MailTimeout))
	defer cancelA()

	_, id, err := mg.Send(ctxA, m)

	if err != nil {

		return fmt.Errorf("Email failed to send: %w", err)
	}

	fmt.Printf("Mail sent successfully, ID: %s\n", id)

	return nil
}

//
// Html File name chhosing based on mfa_type

func HtmlFCase(name string, mailCfg config.MailConfig) (string, time.Duration, error) {

	switch name {

	case enums.MfaRegVerify:
		return "mfa_reg_verify.html", time.Duration(mailCfg.MfaRegExpiry), nil

	case enums.MfaLoginVerify:
		return "mfa_login_verify.html", time.Duration(mailCfg.MfaLoginExpiry), nil

	case enums.MfaForgotPassword:
		return "forgot_pass_verify.html", time.Duration(mailCfg.ForgotPassExpiry), nil

	case enums.MfaChangePassword:
		return "change_pass_verify.html", time.Duration(mailCfg.ChangePassExpiry), nil

	case enums.MfaDeleteVerify:
		return "mfa_delete_verify.html", time.Duration(mailCfg.MfaDeleteExpiry), nil

	default:
		return "", 0 * time.Second, errors.New("MailFuncApiName went wrong")
	}

}
