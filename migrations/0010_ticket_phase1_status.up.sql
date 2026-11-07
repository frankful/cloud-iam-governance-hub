ALTER TABLE iam_ticket
    DROP CONSTRAINT IF EXISTS iam_ticket_status_check;

ALTER TABLE iam_ticket
    ADD CONSTRAINT iam_ticket_status_check
        CHECK (status IN (
            'DRAFT', 'APPROVING', 'APPROVED', 'PUBLISHING', 'PUBLISH_FAILED',
            'REJECTED', 'MERGED', 'CLOSED'
        )),
    ADD COLUMN git_provider VARCHAR(16),
    ADD COLUMN git_repository VARCHAR(256),
    ADD COLUMN remote_request_number VARCHAR(64),
    ADD COLUMN git_commit_sha VARCHAR(128),
    ADD COLUMN poll_attempt_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN next_poll_at TIMESTAMPTZ,
    ADD COLUMN last_status_poll_at TIMESTAMPTZ,
    ADD COLUMN closed_at TIMESTAMPTZ,
    ADD COLUMN closed_by VARCHAR(128) REFERENCES platform_user(user_id) ON DELETE SET NULL,
    ADD COLUMN closure_reason VARCHAR(16),
    ADD CONSTRAINT iam_ticket_poll_attempt_count_check CHECK (poll_attempt_count >= 0),
    ADD CONSTRAINT iam_ticket_git_provider_check
        CHECK (git_provider IS NULL OR git_provider IN ('GITHUB', 'GITLAB')),
    ADD CONSTRAINT iam_ticket_closure_reason_check
        CHECK (closure_reason IS NULL OR closure_reason IN ('APPLIED', 'ABANDONED')),
    ADD CONSTRAINT iam_ticket_closed_state_reason_check
        CHECK (
            (status = 'CLOSED' AND closure_reason IS NOT NULL AND closed_at IS NOT NULL)
            OR
            (status <> 'CLOSED' AND closure_reason IS NULL AND closed_at IS NULL)
        );

CREATE INDEX iam_ticket_status_created_idx ON iam_ticket (status, created_at DESC, id DESC);
CREATE INDEX iam_ticket_account_status_created_idx
    ON iam_ticket (account_id, status, created_at DESC, id DESC);
CREATE INDEX iam_ticket_pending_poll_idx
    ON iam_ticket (next_poll_at, id) WHERE next_poll_at IS NOT NULL;
