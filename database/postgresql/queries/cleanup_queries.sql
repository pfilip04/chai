-- name: CleanupExpiredSessions :exec
DELETE FROM sessions 
WHERE expires_at<NOW();

-- name: CleanupExpiredMfaMail :exec
DELETE FROM mfa_mail 
WHERE expires_at<NOW();

-- name: CleanupExpiredMfaSessions :exec
DELETE FROM mfa_session 
WHERE expires_at<NOW();