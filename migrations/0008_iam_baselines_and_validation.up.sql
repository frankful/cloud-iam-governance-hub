CREATE TABLE iam_baseline (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES aws_account(id) ON DELETE RESTRICT,
    version INTEGER NOT NULL CHECK (version > 0),
    abstract_policy JSONB NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_by VARCHAR(128) REFERENCES platform_user(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT iam_baseline_account_version_unique UNIQUE (account_id, version),
    CONSTRAINT iam_baseline_policy_object_check
        CHECK (jsonb_typeof(abstract_policy) = 'object')
);

CREATE UNIQUE INDEX iam_baseline_one_enabled_per_account_idx
    ON iam_baseline (account_id) WHERE enabled = TRUE;
CREATE INDEX iam_baseline_account_created_idx
    ON iam_baseline (account_id, created_at DESC);

CREATE FUNCTION prevent_iam_baseline_content_mutation()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.account_id IS DISTINCT FROM NEW.account_id
       OR OLD.version IS DISTINCT FROM NEW.version
       OR OLD.abstract_policy IS DISTINCT FROM NEW.abstract_policy
       OR OLD.created_by IS DISTINCT FROM NEW.created_by
       OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION 'IAM baseline content is immutable; create a new version';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER iam_baseline_content_immutable
    BEFORE UPDATE ON iam_baseline
    FOR EACH ROW
    EXECUTE FUNCTION prevent_iam_baseline_content_mutation();

CREATE TABLE ticket_validation_record (
    id BIGSERIAL PRIMARY KEY,
    ticket_id BIGINT NOT NULL REFERENCES iam_ticket(id) ON DELETE RESTRICT,
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    baseline_id BIGINT REFERENCES iam_baseline(id) ON DELETE RESTRICT,
    request_sha256 BYTEA NOT NULL,
    result VARCHAR(16) NOT NULL,
    checks JSONB NOT NULL,
    skipped_checks JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ticket_validation_request_hash_length_check
        CHECK (octet_length(request_sha256) = 32),
    CONSTRAINT ticket_validation_result_check
        CHECK (result IN ('PASSED', 'BLOCKED', 'ERROR')),
    CONSTRAINT ticket_validation_checks_array_check
        CHECK (jsonb_typeof(checks) = 'array'),
    CONSTRAINT ticket_validation_skipped_array_check
        CHECK (jsonb_typeof(skipped_checks) = 'array'),
    CONSTRAINT ticket_validation_ticket_attempt_unique UNIQUE (ticket_id, attempt)
);

CREATE INDEX ticket_validation_ticket_created_idx
    ON ticket_validation_record (ticket_id, created_at DESC);

CREATE FUNCTION prevent_ticket_validation_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'ticket_validation_record is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER ticket_validation_record_append_only
    BEFORE UPDATE OR DELETE ON ticket_validation_record
    FOR EACH ROW
    EXECUTE FUNCTION prevent_ticket_validation_mutation();
