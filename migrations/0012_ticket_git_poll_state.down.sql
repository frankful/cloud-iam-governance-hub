ALTER TABLE iam_ticket
    DROP CONSTRAINT IF EXISTS iam_ticket_git_merge_state_check,
    DROP CONSTRAINT IF EXISTS iam_ticket_git_ci_state_check,
    DROP CONSTRAINT IF EXISTS iam_ticket_git_apply_result_check,
    DROP COLUMN IF EXISTS git_apply_result,
    DROP COLUMN IF EXISTS git_ci_state,
    DROP COLUMN IF EXISTS git_merge_state;
