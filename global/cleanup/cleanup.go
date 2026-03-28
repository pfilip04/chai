package cleanup

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/loggr"
)

func CleanupTX(ctx context.Context, db *pgxpool.Pool) error {

	ctxA, cancelA := context.WithTimeout(ctx, 30*time.Second)
	defer cancelA()

	tx, err := db.Begin(ctxA)

	if err != nil {

		return fmt.Errorf("Transaction start problem: %w", err)
	}

	defer tx.Rollback(ctxA)

	repo := repository.New(tx)

	if err := repo.CleanupExpiredSessions(ctxA); err != nil {

		return fmt.Errorf("Expired sessions cleanup problem: %w", err)
	}

	if err := repo.CleanupExpiredMfaSessions(ctxA); err != nil {

		return fmt.Errorf("Expired mfa sessions cleanup problem: %w", err)
	}

	if err := repo.CleanupExpiredMfaMail(ctxA); err != nil {

		return fmt.Errorf("Expired mfa mail cleanup problem: %w", err)
	}

	return tx.Commit(ctxA)
}

func GlobalCleanup(ctx context.Context, db *pgxpool.Pool) {

	for {

		time.Sleep(time.Hour)

		if err := CleanupTX(ctx, db); err != nil {

			loggr.Log.Error("problem cleaning up in the DB", "error", err)
		}

	}
}
