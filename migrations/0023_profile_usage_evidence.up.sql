-- 0023: 实例配置文件「在用性证据」落库。
-- 待清理清单判定 eks-<uuid> 孤儿需要 EC2 launch template 引用与 EKS 节点组
-- 角色。这份证据此前每次打开页面都实时调 AWS（AssumeRole + 逐模板读版本 +
-- 逐节点组 Describe，串行 7~25 秒）。现在改为同步时顺带采集、整体落一行，
-- 页面直接读库；未同步过的账号仍可实时回源。
-- 一账号一行（UPSERT 覆盖）：证据只关心「当前谁在用」，历史由 aws_sync_run
-- 记录承担，这里不保留版本史。

CREATE TABLE iam_profile_usage_evidence (
    id BIGSERIAL PRIMARY KEY,
    aws_account_id VARCHAR(20) NOT NULL UNIQUE REFERENCES aws_account(account_id) ON DELETE CASCADE,
    used_profiles JSONB NOT NULL,
    role_nodegroups JSONB NOT NULL,
    warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT iam_profile_usage_evidence_object_check
        CHECK (
            jsonb_typeof(used_profiles) = 'object'
            AND jsonb_typeof(role_nodegroups) = 'object'
            AND jsonb_typeof(warnings) = 'array'
        )
);
