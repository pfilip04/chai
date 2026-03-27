-- name: GetIdentifierByUsernameOrEmail :one
SELECT id, username, email FROM users 
WHERE username=$1 OR email=$1;

-- name: GetIdentifierBySession :one
SELECT user_id FROM sessions 
WHERE session_token=$1;

-- name: GetIdentifierByRefresh :one
SELECT s.user_id FROM refresh_tokens rt
JOIN sessions s ON rt.session_id=s.id
WHERE rt.refresh_token=$1;

-- name: GetIdentifierByMfaSession :one
SELECT user_id FROM mfa_session 
WHERE mfa_session_token=$1;