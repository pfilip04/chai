-- name: CreateUser :exec
INSERT INTO users (username, email, password_hash) 
VALUES ($1, $2, $3);