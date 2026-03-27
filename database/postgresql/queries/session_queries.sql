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

-- name: DeleteCookieSession :execrows
DELETE FROM sessions 
WHERE id=$1;

-- name: DeleteJWTSession :execrows
DELETE FROM sessions 
WHERE id=$1;

-- name: GetSessionIdAndCsrf :one
SELECT id, csrf_token FROM sessions 
WHERE session_token=$1 AND expires_at>NOW();

-- name: GetSessionIdByRefresh :one
SELECT session_id FROM refresh_tokens 
WHERE refresh_token=$1 AND expires_at>NOW();

-- name: GetUserIdBySessionId :one
SELECT user_id FROM sessions 
WHERE id=$1 AND expires_at>NOW();

-- name: UpdateCookieSession :execrows
UPDATE sessions 
SET session_token=$1, csrf_token=$2, expires_at=$3 
WHERE id=$4 AND expires_at>NOW();

-- name: UpdateJWTSession :execrows
UPDATE sessions 
SET expires_at=$1 
WHERE id=$2 AND expires_at>NOW();

-- name: UpdateRefreshToken :execrows
UPDATE refresh_tokens 
SET refresh_token=$1, expires_at=$2 
WHERE refresh_token=$3 AND session_id=$4 AND expires_at>NOW();

-- name: ClearAllSessions :execrows
DELETE FROM sessions 
WHERE user_id=$1;