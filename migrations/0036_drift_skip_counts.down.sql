ALTER TABLE aws_account_config
    DROP COLUMN IF EXISTS last_drift_stale_files,
    DROP COLUMN IF EXISTS last_drift_skipped_files;
