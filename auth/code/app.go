package code

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

//
// Verifying code structs

type VerificationCode struct {
	DB                 *pgxpool.Pool
	queryTimeout       time.Duration
	mfaTokenExpiration time.Duration
}

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

// Verification code initialization

func New(db *pgxpool.Pool, queryTimeout time.Duration, mfaExp time.Duration) *VerificationCode {
	return &VerificationCode{
		DB:                 db,
		queryTimeout:       queryTimeout,
		mfaTokenExpiration: mfaExp,
	}
}
