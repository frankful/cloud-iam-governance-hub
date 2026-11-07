-- Add Git polling state columns to iam_ticket.
-- These track merge/CI/apply state observed by the gitstatus-worker.
ALTER TABLE iam_ticket
    ADD COLUMN git_merge_state VARCHAR(16),
    ADD COLUMN git_ci_state VARCHAR(16),
    ADD COLUMN git_apply_result VARCHAR(16);

ALTER TABLE iam_ticket
    ADD CONSTRAINT iam_ticket_git_merge_state_check
        CHECK (git_merge_state IS NULL OR git_merge_state IN ('OPEN', 'MERGED', 'CLOSED', 'UNKNOWN')),
    ADD CONSTRAINT iam_ticket_git_ci_state_check
        CHECK (git_ci_state IS NULL OR git_ci_state IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELED', 'UNKNOWN')),
    ADD CONSTRAINT iam_ticket_git_apply_result_check
        CHECK (git_apply_result IS NULL OR git_apply_result IN ('PENDING', 'SUCCEEDED', 'FAILED', 'CANCELED', 'UNKNOWN'));
