package router

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/utils"
)

func InitAdminAccount(ctx context.Context, db *pgxpool.Pool, username string, email string, password string) (string, error) {

	ctx5, cancel5 := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel5()

	passwordH, err := utils.HashPassword(password)

	if err != nil {

		return "", fmt.Errorf("Problem when hashing the Admin password: %w", err)
	}

	repo := repository.New(db)

	rows, err := repo.CreateFirstSuperuser(ctx5, repository.CreateFirstSuperuserParams{
		Username:     username,
		Email:        email,
		PasswordHash: passwordH,
	})

	if err != nil {

		return "", fmt.Errorf("Problem when creating the initial Admin user in the db: %w", err)
	}

	if rows == 0 {

		return "Initial Admin user already exists", nil
	}

	return "Initial Admin user successfully created", nil
}
