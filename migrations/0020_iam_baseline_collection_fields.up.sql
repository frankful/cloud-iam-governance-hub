-- 0020: 全量基线前置采集字段。
-- path / permissions_boundary 在 AWS provider 里是 ForceNew，基线缺这些
-- 属性会让首次 apply 重建角色或用户（ARN 变化 -> 所有挂载断裂）。
-- instance profile 与 OIDC/SAML provider 是可声明的独立资源，需要单独落库。

ALTER TABLE iam_principal
    ADD COLUMN path VARCHAR(512) NOT NULL DEFAULT '/',
    ADD COLUMN permissions_boundary_arn VARCHAR(512),
    ADD COLUMN permissions_boundary_type VARCHAR(16);

CREATE TABLE iam_instance_profile (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES aws_account(id) ON DELETE CASCADE,
    instance_profile_name VARCHAR(256) NOT NULL,
    arn VARCHAR(512) NOT NULL UNIQUE,
    path VARCHAR(512) NOT NULL DEFAULT '/',
    role_arn VARCHAR(512),
    tags JSONB,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_iam_instance_profile_account_live
    ON iam_instance_profile (account_id)
    WHERE is_deleted = FALSE;

CREATE TABLE iam_identity_provider (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES aws_account(id) ON DELETE CASCADE,
    provider_type VARCHAR(8) NOT NULL CHECK (provider_type IN ('OIDC', 'SAML')),
    arn VARCHAR(512) NOT NULL UNIQUE,
    provider_name VARCHAR(256) NOT NULL,
    url TEXT,
    client_id_list JSONB,
    thumbprint_list JSONB,
    saml_metadata_document TEXT,
    tags JSONB,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_iam_identity_provider_account_live
    ON iam_identity_provider (account_id)
    WHERE is_deleted = FALSE;
