-- 0035 down: 回滚「已 apply」确认列。
ALTER TABLE iam_baseline_publication
    DROP COLUMN IF EXISTS applied_at,
    DROP COLUMN IF EXISTS applied_commit_sha,
    DROP COLUMN IF EXISTS applied_ci_url;
