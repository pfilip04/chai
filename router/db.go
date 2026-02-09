package router

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func ConnectDB(dbvar string) (*pgxpool.Pool, error) {

	ctx := context.Background()

	//
	// Connecting to the database

	ctx30, cancel30 := context.WithTimeout(ctx, 30*time.Second)
	defer cancel30()

	dbpool, err := pgxpool.New(ctx30, os.Getenv(dbvar))
	if err != nil {
		return nil, fmt.Errorf("Unable to connect to database: %v\n", err)
	}

	//
	// Database check

	ctx5, cancel5 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel5()

	err = dbpool.Ping(ctx5)
	if err != nil {
		dbpool.Close()
		return nil, fmt.Errorf("Database unreachable: %v\n", err)
	}

	return dbpool, nil
}
