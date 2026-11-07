-- 0025: baseline publication ledger (B3).
-- 幂等键 = 账号 + 库存快照 run（D4/D7 拍板）：同一账号同一同步 run 的基线
-- 只发布一次；快照更新（新 run）才允许再发。聚合模式（多账号一个 PR）下
-- 多行共享同一分支与 PR，行仍是逐账号的幂等与审计单位。
CREATE TABLE iam_baseline_publication (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES aws_account(id) ON DELETE CASCADE,
    aws_account_id VARCHAR(12) NOT NULL,
    sync_run_id BIGINT NOT NULL REFERENCES aws_sync_run(id) ON DELETE RESTRICT,
    status VARCHAR(16) NOT NULL DEFAULT 'PUBLISHING'
        CHECK (status IN ('PUBLISHING', 'PUBLISHED', 'FAILED')),
    branch VARCHAR(200) NOT NULL,
    pull_request_url TEXT NOT NULL DEFAULT '',
    remote_request_number VARCHAR(32) NOT NULL DEFAULT '',
    repo_directory TEXT NOT NULL DEFAULT '',
    file_count INTEGER NOT NULL DEFAULT 0 CHECK (file_count >= 0),
    content_sha256 BYTEA CHECK (content_sha256 IS NULL OR octet_length(content_sha256) = 32),
    keep_branch BOOLEAN NOT NULL DEFAULT FALSE,
    counts JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(counts) = 'object'),
    issues JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(issues) = 'array'),
    error TEXT,
    requested_by VARCHAR(255) NOT NULL DEFAULT '',
    published_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT iam_baseline_publication_account_run_key UNIQUE (account_id, sync_run_id),
    CONSTRAINT iam_baseline_publication_published_identity CHECK (
        status <> 'PUBLISHED' OR (pull_request_url <> '' AND published_at IS NOT NULL)
    )
);

CREATE INDEX iam_baseline_publication_account_created_idx
    ON iam_baseline_publication (account_id, created_at DESC);
CREATE INDEX iam_baseline_publication_active_status_idx
    ON iam_baseline_publication (created_at)
    WHERE status = 'PUBLISHING';
