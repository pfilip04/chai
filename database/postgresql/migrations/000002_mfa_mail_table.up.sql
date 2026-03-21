CREATE TABLE IF NOT EXISTS mfa_mail (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    mfa_type            TEXT NOT NULL DEFAULT 'login',
    code                TEXT NOT NULL,

    expires_at          TIMESTAMPTZ NOT NULL,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT possible_mfa_type CHECK (mfa_type IN ('register-verify', 'mfa-login-verify', 'forgot-password-verify', 'change-password-verify')),
    CONSTRAINT uq_user_mfa_type UNIQUE (user_id, mfa_type)
);

CREATE INDEX IF NOT EXISTS idx_mfa_user_code ON mfa_mail(user_id, code);

CREATE TABLE IF NOT EXISTS mfa_session (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    mfa_session_token   TEXT UNIQUE,

    expires_at          TIMESTAMPTZ NOT NULL,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE users 
ADD COLUMN mfa BOOLEAN DEFAULT false;