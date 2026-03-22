BEGIN;

ALTER TABLE users 
ADD COLUMN is_superuser BOOLEAN DEFAULT false, 
ADD COLUMN status TEXT NOT NULL DEFAULT 'active', 
ADD COLUMN deleted_at TIMESTAMPTZ DEFAULT NULL, 
ADD COLUMN suspended_at TIMESTAMPTZ DEFAULT NULL, 
ADD CONSTRAINT possible_status CHECK (
    status IN ('active', 'suspended', 'deleted')
), 
ADD CONSTRAINT status_deleted CHECK (
    (status = 'deleted') = (deleted_at IS NOT NULL)
), 
ADD CONSTRAINT status_suspended CHECK (
    (status = 'suspended') = (suspended_at IS NOT NULL)
);

COMMIT;
