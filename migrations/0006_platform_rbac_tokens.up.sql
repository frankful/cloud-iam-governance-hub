CREATE TABLE platform_role (
    id BIGSERIAL PRIMARY KEY,
    role_code VARCHAR(64) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    is_system BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT platform_role_code_check
        CHECK (role_code IN ('platform_admin', 'approval_admin', 'standard_user'))
);

INSERT INTO platform_role (role_code, description) VALUES
    ('platform_admin', 'Full platform administration'),
    ('approval_admin', 'Ticket approval and operational read access'),
    ('standard_user', 'Self-service access requests')
ON CONFLICT (role_code) DO NOTHING;

CREATE TABLE user_role_mapping (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(128) NOT NULL REFERENCES platform_user(user_id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES platform_role(id) ON DELETE RESTRICT,
    assigned_by VARCHAR(128) REFERENCES platform_user(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT user_role_mapping_user_role_unique UNIQUE (user_id, role_id)
);

CREATE INDEX user_role_mapping_role_user_idx ON user_role_mapping (role_id, user_id);

CREATE TABLE platform_token (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(128) NOT NULL REFERENCES platform_user(user_id) ON DELETE RESTRICT,
    token_hash BYTEA NOT NULL UNIQUE,
    token_prefix VARCHAR(16) NOT NULL,
    token_name VARCHAR(128) NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_by VARCHAR(128) REFERENCES platform_user(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT platform_token_hash_length_check CHECK (octet_length(token_hash) = 32),
    CONSTRAINT platform_token_prefix_check CHECK (length(token_prefix) BETWEEN 4 AND 16),
    CONSTRAINT platform_token_name_check CHECK (length(btrim(token_name)) > 0)
);

CREATE INDEX platform_token_user_active_idx
    ON platform_token (user_id, expires_at) WHERE revoked_at IS NULL;
CREATE INDEX platform_token_prefix_idx ON platform_token (token_prefix);
