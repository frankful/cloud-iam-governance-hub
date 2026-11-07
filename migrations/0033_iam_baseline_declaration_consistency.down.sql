DROP INDEX IF EXISTS iam_baseline_declaration_restore_idx;

ALTER TABLE iam_baseline_declaration
    DROP CONSTRAINT IF EXISTS iam_baseline_declaration_stale_check,
    DROP CONSTRAINT IF EXISTS iam_baseline_declaration_supersede_reason_check,
    DROP CONSTRAINT IF EXISTS iam_baseline_declaration_supersede_check;

ALTER TABLE iam_baseline_declaration
    DROP COLUMN IF EXISTS stale_reason,
    DROP COLUMN IF EXISTS stale_at,
    DROP COLUMN IF EXISTS superseded_reason;
