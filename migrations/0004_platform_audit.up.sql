CREATE TABLE iam_audit_event (
    id BIGSERIAL PRIMARY KEY,
    request_id VARCHAR(128),
    actor_id VARCHAR(128),
    action VARCHAR(128) NOT NULL,
    resource_type VARCHAR(128) NOT NULL,
    resource_id VARCHAR(512),
    outcome VARCHAR(16) NOT NULL CHECK (outcome IN ('SUCCESS', 'FAILURE')),
    http_status INTEGER CHECK (http_status BETWEEN 100 AND 599),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX iam_audit_event_occurred_at_idx ON iam_audit_event (occurred_at DESC);
CREATE INDEX iam_audit_event_actor_action_idx ON iam_audit_event (actor_id, action, occurred_at DESC);
CREATE INDEX iam_audit_event_resource_idx ON iam_audit_event (resource_type, resource_id, occurred_at DESC);

CREATE FUNCTION prevent_iam_audit_event_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'iam_audit_event is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER iam_audit_event_append_only
    BEFORE UPDATE OR DELETE ON iam_audit_event
    FOR EACH ROW
    EXECUTE FUNCTION prevent_iam_audit_event_mutation();
