-- name: CreateUser :one
INSERT INTO users (username, email, password_hash, mfa) 
VALUES ($1, $2, $3, $4) 
RETURNING id;

-- name: GetUserByIdOrUsername :one
SELECT id, username, email, password_hash, email_verified, mfa FROM users 
WHERE username=$1 OR id=$2;

-- name: InsertCookieSession :one
INSERT INTO sessions (user_id, session_token, csrf_token, platform, expires_at) 
VALUES ($1, $2, $3, $4, $5) 
RETURNING id;

-- name: InsertJWTSession :one
INSERT INTO sessions (user_id, platform, expires_at) 
VALUES ($1, $2, $3) 
RETURNING id;

-- name: InsertRefreshToken :exec
INSERT INTO refresh_tokens (session_id, refresh_token, expires_at) 
VALUES ($1, $2, $3);

-- name: DeleteCookieSession :one
DELETE FROM sessions 
WHERE id=$1 
RETURNING user_id;

-- name: DeleteJWTSession :execrows
DELETE FROM sessions 
WHERE id=$1 AND user_id=$2;

-- name: DeleteRefreshToken :execrows
DELETE FROM refresh_tokens 
WHERE session_id=$1;

-- name: DeleteUser :execrows
DELETE FROM users 
WHERE id=$1;

-- name: GetUserIdBySession :one
SELECT user_id FROM sessions 
WHERE session_token=$1 AND expires_at > NOW();

-- name: GetSessionIdAndCsrf :one
SELECT id, csrf_token FROM sessions 
WHERE session_token=$1 AND expires_at > NOW();

-- name: GetSessionIdByRefresh :one
SELECT session_id FROM refresh_tokens 
WHERE refresh_token=$1 AND expires_at > NOW();

-- name: GetUserIdBySessionId :one
SELECT user_id FROM sessions 
WHERE id=$1 AND expires_at > NOW();

-- name: UpdateUserPassword :execrows
UPDATE users 
SET password_hash=$1, updated_at=$2 
WHERE id=$3;

-- name: UpdateCookieSession :execrows
UPDATE sessions 
SET session_token=$1, csrf_token=$2, expires_at=$3 
WHERE id=$4 AND expires_at > NOW();

-- name: UpdateJWTSession :execrows
UPDATE sessions 
SET expires_at=$1 
WHERE id=$2;

-- name: UpdateRefreshToken :execrows
UPDATE refresh_tokens 
SET refresh_token=$1, expires_at=$2 
WHERE refresh_token=$3 AND session_id=$4 AND expires_at > NOW();

-- name: CountUsername :one
SELECT COUNT(*) FROM users 
WHERE username=$1;

-- name: CountEmail :one
SELECT COUNT(*) FROM users 
WHERE email=$1;

-- name: CreateMfaMail :one
INSERT INTO mfa_mail (user_id, mfa_type, code, expires_at) 
VALUES ($1, $2, $3, $4) 
ON CONFLICT (user_id, mfa_type) 
DO UPDATE 
SET code = EXCLUDED.code, 
    expires_at = EXCLUDED.expires_at, 
    created_at = now()
RETURNING id;

-- name: CheckVerificationCode :one
SELECT user_id, code FROM mfa_mail 
WHERE id=$1 AND mfa_type=$2 AND expires_at > NOW();

-- name: ClearMfaMail :execrows
DELETE FROM mfa_mail 
WHERE id=$1;

-- name: FindUserByUsernameOrEmail :one
SELECT id, username, email FROM users 
WHERE username=$1 OR email=$1;

-- name: CreateMfaSession :exec
INSERT INTO mfa_session (user_id, mfa_session_token, expires_at) 
VALUES ($1, $2, $3);

-- name: CheckMfaSession :one
SELECT user_id FROM mfa_session
WHERE mfa_session_token=$1 AND expires_at > NOW();

-- name: ClearMfaSessions :execrows
DELETE FROM mfa_session 
WHERE user_id=$1;
