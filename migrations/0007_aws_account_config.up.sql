CREATE TABLE aws_account_config (
    id BIGSERIAL PRIMARY KEY,
    aws_account_id VARCHAR(12) NOT NULL UNIQUE,
    aws_account_db_id BIGINT UNIQUE REFERENCES aws_account(id) ON DELETE SET NULL,
    organization_db_id BIGINT REFERENCES aws_organization(id) ON DELETE RESTRICT,
    display_name VARCHAR(256) NOT NULL,
    read_only_role_arn VARCHAR(512),
    sync_mode VARCHAR(32) NOT NULL,
    sync_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    tags JSONB NOT NULL DEFAULT '{}'::jsonb,
    sync_status VARCHAR(16) NOT NULL DEFAULT 'NEVER',
    last_sync_attempt_at TIMESTAMPTZ,
    last_successful_sync_at TIMESTAMPTZ,
    last_sync_error TEXT,
    created_by VARCHAR(128) REFERENCES platform_user(user_id) ON DELETE SET NULL,
    updated_by VARCHAR(128) REFERENCES platform_user(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT aws_account_config_account_id_check
        CHECK (aws_account_id ~ '^[0-9]{12}$'),
    CONSTRAINT aws_account_config_display_name_check
        CHECK (length(btrim(display_name)) > 0),
    CONSTRAINT aws_account_config_sync_mode_check
        CHECK (sync_mode IN ('ASSUME_ROLE', 'CURRENT_CREDENTIALS')),
    CONSTRAINT aws_account_config_role_check
        CHECK (
            (sync_mode = 'ASSUME_ROLE' AND read_only_role_arn IS NOT NULL
                AND read_only_role_arn ~ '^arn:aws(-[a-z0-9-]+)?:iam::[0-9]{12}:role/.+$'
                AND split_part(read_only_role_arn, ':', 5) = aws_account_id)
            OR
            (sync_mode = 'CURRENT_CREDENTIALS' AND read_only_role_arn IS NULL)
        ),
    CONSTRAINT aws_account_config_sync_status_check
        CHECK (sync_status IN ('NEVER', 'RUNNING', 'SUCCEEDED', 'FAILED', 'DISABLED')),
    CONSTRAINT aws_account_config_tags_object_check
        CHECK (jsonb_typeof(tags) = 'object')
);

CREATE INDEX aws_account_config_enabled_idx
    ON aws_account_config (sync_mode, aws_account_id) WHERE sync_enabled = TRUE;
CREATE INDEX aws_account_config_organization_idx
    ON aws_account_config (organization_db_id, aws_account_id);
