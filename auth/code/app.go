package code

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DbQuery struct {
	Db           *pgxpool.Pool
	queryTimeout time.Duration
	ctx          context.Context
}

type Credentials struct {
	mfaId   uuid.UUID
	code    string
	apiName string
}
