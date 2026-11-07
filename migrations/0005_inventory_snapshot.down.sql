DROP INDEX IF EXISTS iam_principal_account_active_idx;

ALTER TABLE iam_principal
    DROP COLUMN IF EXISTS is_deleted,
    DROP COLUMN IF EXISTS last_seen_at;
