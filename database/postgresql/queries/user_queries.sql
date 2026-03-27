-- name: CreateUser :one
INSERT INTO users (username, email, password_hash, mfa) 
VALUES ($1, $2, $3, $4) 
RETURNING id;

-- name: CreateFirstSuperuser :execrows
INSERT INTO users (username, email, password_hash, is_superuser, mfa, email_verified) 
VALUES ($1, $2, $3, true, true, true)
ON CONFLICT DO NOTHING;

-- name: GetUserByUsernameOrEmail :one
SELECT id, username, email, password_hash, email_verified, status, suspended_at, suspended_for, deleted_at, mfa FROM users 
WHERE username=$1 OR email=$1;

-- name: FindUserByUsernameOrEmail :one
SELECT id, username, email FROM users 
WHERE username=$1 OR email=$1;

-- name: GetUserById :one
SELECT username, email, password_hash, mfa FROM users 
WHERE id=$1;

-- name: HardDeleteUser :execrows
DELETE FROM users 
WHERE id=$1;

-- name: SoftDeleteUser :execrows
UPDATE users 
SET status='deleted', deleted_at=NOW() 
WHERE id=$1;

-- name: SuspendUser :execrows
UPDATE users 
SET status='suspended', suspended_at=NOW(), suspended_for=$2 
WHERE id=$1;

-- name: GetUserIdBySession :one
SELECT user_id FROM sessions 
WHERE session_token=$1 AND expires_at>NOW();

-- name: UpdateUserPassword :execrows
UPDATE users 
SET password_hash=$1, updated_at=$2 
WHERE id=$3;

-- name: UsernameExists :one
SELECT EXISTS (
    SELECT 1 FROM users WHERE username=$1
);

-- name: EmailExists :one
SELECT EXISTS (
    SELECT 1 FROM users WHERE email=$1
);

-- name: GetSuperuserStatus :one
SELECT is_superuser from users 
WHERE id=$1;

-- name: PromoteSuperuser :execrows
UPDATE users 
SET is_superuser=true, updated_at=NOW() 
WHERE id=$1;

-- name: ReviveUser :execrows
UPDATE users 
SET status='active', deleted_at=NULL, suspended_at=NULL, suspended_for=NULL 
WHERE id=$1;