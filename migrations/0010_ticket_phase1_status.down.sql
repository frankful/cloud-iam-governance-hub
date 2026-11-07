DROP INDEX IF EXISTS iam_ticket_pending_poll_idx;
DROP INDEX IF EXISTS iam_ticket_account_status_created_idx;
DROP INDEX IF EXISTS iam_ticket_status_created_idx;

ALTER TABLE iam_ticket
    DROP CONSTRAINT IF EXISTS iam_ticket_closed_state_reason_check,
    DROP CONSTRAINT IF EXISTS iam_ticket_closure_reason_check,
    DROP CONSTRAINT IF EXISTS iam_ticket_git_provider_check,
    DROP CONSTRAINT IF EXISTS iam_ticket_poll_attempt_count_check,
    DROP CONSTRAINT IF EXISTS iam_ticket_status_check,
    DROP COLUMN IF EXISTS closure_reason,
    DROP COLUMN IF EXISTS closed_by,
    DROP COLUMN IF EXISTS closed_at,
    DROP COLUMN IF EXISTS last_status_poll_at,
    DROP COLUMN IF EXISTS next_poll_at,
    DROP COLUMN IF EXISTS poll_attempt_count,
    DROP COLUMN IF EXISTS git_commit_sha,
    DROP COLUMN IF EXISTS remote_request_number,
    DROP COLUMN IF EXISTS git_repository,
    DROP COLUMN IF EXISTS git_provider;

ALTER TABLE iam_ticket
    ADD CONSTRAINT iam_ticket_status_check
        CHECK (status IN ('DRAFT', 'APPROVING', 'APPROVED', 'PUBLISHING', 'REJECTED', 'MERGED'));
