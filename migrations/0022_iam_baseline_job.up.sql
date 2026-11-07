-- 0022: 全量基线预览 job。
-- 一次预览 = 从库存构建多文件 Terraform bundle（含 import 块）+ 冲突检测，
-- 结果整体落 JSONB 供前端只读展示。job 是状态机（PENDING → RUNNING →
-- COMPLETED/FAILED），结果与哈希只在终态写入；归属与创建时间不可变。

CREATE TABLE iam_baseline_job (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES aws_account(id) ON DELETE RESTRICT,
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')),
    requested_by VARCHAR(128) REFERENCES platform_user(user_id) ON DELETE SET NULL,
    error TEXT NOT NULL DEFAULT '',
    result JSONB,
    content_sha256 BYTEA,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT iam_baseline_job_result_object_check
        CHECK (result IS NULL OR jsonb_typeof(result) = 'object'),
    CONSTRAINT iam_baseline_job_hash_length_check
        CHECK (content_sha256 IS NULL OR octet_length(content_sha256) = 32)
);

CREATE INDEX iam_baseline_job_account_created_idx
    ON iam_baseline_job (account_id, created_at DESC);

-- 归属与创建时间不可变；状态机之外的列（error/result/hash/时间戳）随状态
-- 一起推进，允许更新。误把 job 挂到别的账号、或事后改经办人都会被拒绝。
CREATE FUNCTION prevent_iam_baseline_job_identity_mutation()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.account_id IS DISTINCT FROM NEW.account_id
       OR OLD.requested_by IS DISTINCT FROM NEW.requested_by
       OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION 'iam_baseline_job identity columns are immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER iam_baseline_job_identity_immutable
    BEFORE UPDATE ON iam_baseline_job
    FOR EACH ROW
    EXECUTE FUNCTION prevent_iam_baseline_job_identity_mutation();
