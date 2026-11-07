-- 0013: per-run history for manual (API-triggered) AWS account synchronization.
-- aws_account_config only keeps the last attempt; this table records every run.
CREATE TABLE aws_sync_run (
    id BIGSERIAL PRIMARY KEY,
    aws_account_config_id BIGINT NOT NULL REFERENCES aws_account_config(id) ON DELETE CASCADE,
    aws_account_id VARCHAR(12) NOT NULL,
    trigger_source VARCHAR(16) NOT NULL DEFAULT 'MANUAL' CHECK (trigger_source IN ('MANUAL')),
    triggered_by VARCHAR(255) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED')),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX aws_sync_run_config_created_idx
    ON aws_sync_run (aws_account_config_id, created_at DESC);
CREATE INDEX aws_sync_run_active_status_idx
    ON aws_sync_run (aws_account_config_id)
    WHERE status IN ('PENDING', 'RUNNING');
