package mailing

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pfilip04/chai/config"
	"github.com/pfilip04/chai/database/postgresql/repository"
)

type User struct {
	UserID    uuid.UUID
	Username  string
	UserEmail string
}

type Verification struct {
	Id      uuid.UUID
	ApiName string
	Code    string
}

type Sender struct {
	SenderName string
	Fulldomain string
	Domain     string
	ApiKey     string
}

func (u *User) ToUser() string {
	return fmt.Sprintf("%s <%s>", u.Username, u.UserEmail)

}

func (s *Sender) FromSender() string {
	return fmt.Sprintf("%s <%s>", s.SenderName, s.Fulldomain)
}

func NewSender(name string, fdomain string, domain string, apikey string) *Sender {
	return &Sender{
		SenderName: name,
		Fulldomain: fdomain,
		Domain:     domain,
		ApiKey:     apikey,
	}
}

func ToLink(name string, fulldomain string, id uuid.UUID) string {
	return fmt.Sprintf("%s/code/%s?id=%s", fulldomain, name, id.String())
}

type DbQuerying struct {
	Repo         *repository.Queries
	QueryTimeout time.Duration
	Ctx          context.Context
}

type MfaType struct {
	ApiName  string
	MailName string
}

type Mailc struct {
	MExp    config.Duration
	MailCfg config.MailConfig
}
