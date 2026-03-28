CREATE TABLE IF NOT EXISTS users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    username	        TEXT NOT NULL UNIQUE,
    email               TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,

    mfa                 BOOLEAN DEFAULT false,
    email_verified      BOOLEAN NOT NULL DEFAULT false,

    is_superuser        BOOLEAN DEFAULT false,
    status              TEXT NOT NULL DEFAULT 'active',
    
    suspended_for       INTERVAL DEFAULT NULL,
    
    deleted_at          TIMESTAMPTZ DEFAULT NULL,
    suspended_at        TIMESTAMPTZ DEFAULT NULL,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT possible_status CHECK (status IN ('active', 'suspended', 'deleted')), 
    CONSTRAINT status_deleted CHECK ((status = 'deleted') = (deleted_at IS NOT NULL)), 
    CONSTRAINT status_suspended CHECK ((status = 'suspended') = (suspended_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    session_token       TEXT UNIQUE,
    csrf_token          TEXT,

    platform            TEXT NOT NULL,

    expires_at          TIMESTAMPTZ NOT NULL,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id          UUID REFERENCES sessions(id) ON DELETE CASCADE,

    refresh_token       TEXT NOT NULL UNIQUE,
    expires_at          TIMESTAMPTZ NOT NULL,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_refresh_session_id ON refresh_tokens(session_id);

CREATE TABLE IF NOT EXISTS mfa_mail (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    mfa_type            TEXT NOT NULL DEFAULT 'login',
    code                TEXT NOT NULL,

    expires_at          TIMESTAMPTZ NOT NULL,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT possible_mfa_type CHECK (
        mfa_type IN ('register-verify', 'mfa-login-verify', 'forgot-password-verify', 'change-password-verify', 'mfa-delete-verify')),
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

