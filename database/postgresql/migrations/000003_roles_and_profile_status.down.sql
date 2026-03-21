ALTER TABLE users 
DROP COLUMN is_superuser BOOLEAN DEFAULT false, 
DROP COLUMN status TEXT NOT NULL DEFAULT 'active', 
DROP COLUMN deleted_at TIMESTAMPTZ DEFAULT NULL, 
DROP COLUMN suspended_at TIMESTAMPTZ DEFAULT NULL, 
DROP CONSTRAINT possible_status CHECK (
    status IN ('active', 'suspended', 'deleted')
);
DROP CONSTRAINT status_deleted CHECK (
    (status = 'deleted') = (deleted_at IS NOT NULL)
)
DROP CONSTRAINT status_suspended CHECK (
    (status = 'suspended') = (suspended_at IS NOT NULL)
);