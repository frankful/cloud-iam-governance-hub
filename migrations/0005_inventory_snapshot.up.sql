ALTER TABLE iam_principal
    ADD COLUMN last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN is_deleted BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX iam_principal_account_active_idx
    ON iam_principal (account_id, id) WHERE is_deleted = FALSE;
