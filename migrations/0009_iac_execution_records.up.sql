CREATE TABLE iac_execution_record (
    id BIGSERIAL PRIMARY KEY,
    ticket_id BIGINT NOT NULL REFERENCES iam_ticket(id) ON DELETE RESTRICT,
    provider VARCHAR(16) NOT NULL,
    repository VARCHAR(256) NOT NULL,
    remote_request_number VARCHAR(64),
    remote_url VARCHAR(1024),
    commit_sha VARCHAR(128),
    pipeline_id VARCHAR(128),
    merge_state VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN',
    ci_state VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN',
    apply_result VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN',
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    idempotency_key VARCHAR(256) NOT NULL UNIQUE,
    sanitized_error TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT iac_execution_provider_check CHECK (provider IN ('GITHUB', 'GITLAB')),
    CONSTRAINT iac_execution_merge_state_check
        CHECK (merge_state IN ('OPEN', 'MERGED', 'CLOSED', 'UNKNOWN')),
    CONSTRAINT iac_execution_ci_state_check
        CHECK (ci_state IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELED', 'UNKNOWN')),
    CONSTRAINT iac_execution_apply_result_check
        CHECK (apply_result IN ('PENDING', 'SUCCEEDED', 'FAILED', 'CANCELED', 'UNKNOWN')),
    CONSTRAINT iac_execution_metadata_object_check
        CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX iac_execution_ticket_observed_idx
    ON iac_execution_record (ticket_id, observed_at DESC, id DESC);
CREATE INDEX iac_execution_ci_state_observed_idx
    ON iac_execution_record (ci_state, observed_at DESC);
CREATE INDEX iac_execution_remote_request_idx
    ON iac_execution_record (provider, repository, remote_request_number);

CREATE FUNCTION prevent_iac_execution_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'iac_execution_record is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER iac_execution_record_append_only
    BEFORE UPDATE OR DELETE ON iac_execution_record
    FOR EACH ROW
    EXECUTE FUNCTION prevent_iac_execution_mutation();
