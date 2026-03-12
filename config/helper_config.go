package config

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/pfilip04/chai/database/postgresql/repository"
)

type DbQuerying struct {
	Repo         *repository.Queries
	QueryTimeout time.Duration
	Ctx          context.Context
}

type Mailc struct {
	MExp    Duration
	MailCfg MailConfig
}

type User struct {
	UserID   uuid.UUID
	Username string
	Email    string
}

type MfaType struct {
	ApiName  string
	MailName string
}
