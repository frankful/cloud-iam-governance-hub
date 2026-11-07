ALTER TABLE aws_account_config
    DROP COLUMN IF EXISTS last_drift_clean_at,
    DROP COLUMN IF EXISTS last_drift_check_at;

DROP TABLE IF EXISTS iam_drift_finding;
