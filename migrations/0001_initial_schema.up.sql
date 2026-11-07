SET statement_timeout = 0;

CREATE TABLE aws_organization (
    id BIGSERIAL PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL UNIQUE,
    master_account_id VARCHAR(20) NOT NULL,
    name VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE aws_account (
    id BIGSERIAL PRIMARY KEY,
    org_id BIGINT REFERENCES aws_organization(id),
    account_id VARCHAR(20) NOT NULL UNIQUE,
    account_name VARCHAR(128),
    status VARCHAR(32),
    read_only_role_arn VARCHAR(512),
    last_sync_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE iam_principal (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT REFERENCES aws_account(id),
    principal_type VARCHAR(16) NOT NULL,
    principal_name VARCHAR(256) NOT NULL,
    arn VARCHAR(512) NOT NULL UNIQUE,
    trust_policy JSONB,
    description TEXT,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE iam_policy (
    id BIGSERIAL PRIMARY KEY,
    policy_arn VARCHAR(512) UNIQUE,
    policy_name VARCHAR(256),
    policy_type VARCHAR(16),
    policy_document JSONB NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE iam_principal_policy (
    id BIGSERIAL PRIMARY KEY,
    principal_id BIGINT REFERENCES iam_principal(id) ON DELETE CASCADE,
    policy_id BIGINT REFERENCES iam_policy(id) ON DELETE CASCADE,
    CONSTRAINT iam_principal_policy_principal_policy_unique UNIQUE (principal_id, policy_id)
);

CREATE TABLE iam_relationship (
    id BIGSERIAL PRIMARY KEY,
    principal_id BIGINT REFERENCES iam_principal(id) ON DELETE CASCADE,
    action VARCHAR(256) NOT NULL,
    resource VARCHAR(512) NOT NULL,
    source_json JSONB,
    sync_version VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE iam_risk (
    id BIGSERIAL PRIMARY KEY,
    principal_id BIGINT REFERENCES iam_principal(id) ON DELETE CASCADE,
    risk_type VARCHAR(128),
    risk_level VARCHAR(16),
    description TEXT,
    is_resolved BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

-- event_time is stored as UTC without a session-time-zone dependency so the
-- date expression in the unique index is immutable and deterministic.
CREATE TABLE iam_access_log (
    id BIGSERIAL PRIMARY KEY,
    principal_arn VARCHAR(512),
    action VARCHAR(256),
    resource VARCHAR(512),
    event_time TIMESTAMP NOT NULL,
    event_source VARCHAR(256),
    event_name VARCHAR(256),
    raw_event JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX iam_access_log_principal_action_resource_date_unique
    ON iam_access_log (principal_arn, action, resource, (event_time::date));

CREATE TABLE iam_ticket (
    id BIGSERIAL PRIMARY KEY,
    ticket_no VARCHAR(64) NOT NULL UNIQUE,
    ticket_type VARCHAR(32) NOT NULL,
    account_id BIGINT REFERENCES aws_account(id),
    principal_name VARCHAR(256),
    request_policy JSONB NOT NULL,
    terraform_code TEXT,
    git_pr_url VARCHAR(512),
    status VARCHAR(32) NOT NULL
        CHECK (status IN ('DRAFT', 'APPROVING', 'APPROVED', 'PUBLISHING', 'REJECTED', 'MERGED')),
    submitter VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ticket_approval (
    id BIGSERIAL PRIMARY KEY,
    ticket_id BIGINT NOT NULL REFERENCES iam_ticket(id) ON DELETE CASCADE,
    approver VARCHAR(128) NOT NULL,
    approval_result VARCHAR(16),
    comment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX iam_account_org_id_idx ON aws_account (org_id);
CREATE INDEX iam_principal_account_id_idx ON iam_principal (account_id);
CREATE INDEX iam_principal_policy_policy_id_idx ON iam_principal_policy (policy_id);
CREATE INDEX iam_relationship_principal_id_idx ON iam_relationship (principal_id);
CREATE INDEX iam_risk_principal_id_idx ON iam_risk (principal_id);
CREATE INDEX iam_ticket_account_id_idx ON iam_ticket (account_id);
CREATE INDEX iam_ticket_status_idx ON iam_ticket (status);
CREATE INDEX ticket_approval_ticket_id_idx ON ticket_approval (ticket_id);
