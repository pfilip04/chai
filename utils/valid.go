package utils

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pfilip04/chai/database/postgresql/repository"
	"github.com/pfilip04/chai/global/errs"
)

//
// Username feng-shui

func IsValidUsername(username string) bool {

	if len(username) < 3 || len(username) > 15 {

		return false
	}

	firstChar := username[0]
	lastChar := username[len(username)-1]

	if firstChar == '.' || firstChar == '_' || lastChar == '.' || lastChar == '_' {

		return false
	}

	previousChar := rune(0)
	for _, char := range username {

		if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '_' || char == '.') {

			return false
		}

		if char == '.' && previousChar == char {

			return false
		}

		previousChar = char
	}

	return true
}

//
// Password feng-shui

func IsValidPassword(password string) bool {

	if len(password) < 8 || len(password) > 32 {

		return false
	}

	isDigit := false
	isUpper := false

	for _, char := range password {

		if char < 33 || char > 126 {

			return false
		}

		if char >= '0' && char <= '9' {

			isDigit = true
		}

		if char >= 'A' && char <= 'Z' {

			isUpper = true
		}
	}

	return isDigit && isUpper
}

//
// Email check

func IsValidEmail(email string) bool {

	_, err := mail.ParseAddress(email)

	if err != nil {

		return false
	}

	return true
}

//
// String to Boolean function (only strings "true" and "false" with various casing - Case insensitive)

func ToBool(p string) (bool, error) {

	boolean := strings.ToLower(p)

	switch boolean {

	case "true":
		return true, nil

	case "false":
		return false, nil
	}

	return false, errors.New("Couldn't parse to bool")
}

//
// Checks if the user with forwarded user id is superuser

func IsAdmin(r *http.Request, userId uuid.UUID, db *pgxpool.Pool, timeout time.Duration) (bool, error) {

	ctxA, cancelA := context.WithTimeout(r.Context(), timeout)
	defer cancelA()

	repo := repository.New(db)

	superuser, err := repo.GetSuperuserStatus(ctxA, userId)

	if err != nil {

		return false, fmt.Errorf("Problem when fetching superuser status from the db: %w", err)
	}

	return superuser, nil
}

func IsValidStatus(r *http.Request, userId uuid.UUID, status string, suspAt time.Time, suspFor time.Duration,
	delAt time.Time, db *pgxpool.Pool, timeout time.Duration) error {

	if status == "active" {

		return nil
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	repo := repository.New(db)

	switch status {

	case "suspended":

		elapsed := time.Since(suspAt)

		if elapsed > suspFor {

			rows, err := repo.ReviveUser(ctx, userId)

			if err != nil {

				return fmt.Errorf("Couldn't unrestrict user: %w", err)
			}

			if rows == 0 {

				return errors.New("No users unrestricted")
			}

			return nil
		}

		return errs.ForbiddenError.Err

	case "deleted":

		elapsed := time.Since(delAt)
		window := 30 * 24 * time.Hour

		if elapsed <= window {

			rows, err := repo.ReviveUser(ctx, userId)

			if err != nil {

				return fmt.Errorf("Couldn't revive user: %w", err)
			}

			if rows == 0 {

				return errors.New("No users revived")
			}

			return nil
		}

		rows, err := repo.HardDeleteUser(ctx, userId)

		if err != nil {

			return fmt.Errorf("Couldn't delete user: %w", err)
		}

		if rows == 0 {

			return errors.New("No users deleted")
		}

		return errs.ForbiddenError.Err

	default:

		return fmt.Errorf("Unknown status: %s", status)
	}
}
