CREATE TABLE iam_group (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES aws_account(id) ON DELETE CASCADE,
    group_name VARCHAR(256) NOT NULL,
    arn VARCHAR(512) NOT NULL UNIQUE,
    path VARCHAR(512) NOT NULL DEFAULT '/',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX iam_group_account_id_idx ON iam_group (account_id);

CREATE TABLE iam_group_membership (
    id BIGSERIAL PRIMARY KEY,
    group_id BIGINT NOT NULL REFERENCES iam_group(id) ON DELETE CASCADE,
    user_principal_id BIGINT NOT NULL REFERENCES iam_principal(id) ON DELETE CASCADE,
    CONSTRAINT iam_group_membership_group_user_unique UNIQUE (group_id, user_principal_id)
);

CREATE INDEX iam_group_membership_user_principal_id_idx
    ON iam_group_membership (user_principal_id);

CREATE TABLE iam_group_policy (
    id BIGSERIAL PRIMARY KEY,
    group_id BIGINT NOT NULL REFERENCES iam_group(id) ON DELETE CASCADE,
    policy_id BIGINT NOT NULL REFERENCES iam_policy(id) ON DELETE CASCADE,
    CONSTRAINT iam_group_policy_group_policy_unique UNIQUE (group_id, policy_id)
);

CREATE INDEX iam_group_policy_policy_id_idx ON iam_group_policy (policy_id);
