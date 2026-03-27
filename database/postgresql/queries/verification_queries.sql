-- name: CreateMfaMail :one
INSERT INTO mfa_mail (user_id, mfa_type, code, expires_at) 
VALUES ($1, $2, $3, $4) 
ON CONFLICT (user_id, mfa_type) 
DO UPDATE 
SET code=EXCLUDED.code, 
    expires_at=EXCLUDED.expires_at, 
    created_at=NOW()
RETURNING id;

-- name: ConsumeVerificationCode :one
DELETE FROM mfa_mail 
WHERE id=$1 AND mfa_type=$2 AND code=$3 AND expires_at>NOW() 
RETURNING user_id;

-- name: CreateMfaSession :exec
INSERT INTO mfa_session (user_id, mfa_session_token, expires_at) 
VALUES ($1, $2, $3);

-- name: CheckMfaSession :one
SELECT user_id FROM mfa_session 
WHERE mfa_session_token=$1 AND expires_at>NOW();

-- name: ClearMfaSessions :execrows
DELETE FROM mfa_session 
WHERE user_id=$1;

-- name: VerifyEmail :execrows
UPDATE users 
SET email_verified=true, updated_at=NOW() 
WHERE id=$1;