CREATE TABLE platform_user (
    user_id VARCHAR(128) PRIMARY KEY, -- stable platform/SSO subject, not an AWS IAM identity
    display_name VARCHAR(256) NOT NULL,
    email VARCHAR(320),
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE aws_account_approver (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES aws_account(id) ON DELETE CASCADE,
    user_id VARCHAR(128) NOT NULL REFERENCES platform_user(user_id),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (account_id, user_id)
);

ALTER TABLE iam_ticket
    ADD COLUMN approval_mode VARCHAR(16) NOT NULL DEFAULT 'MANUAL',
    ADD COLUMN approver_ids JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE iam_ticket
    ADD CONSTRAINT iam_ticket_approval_mode_check
        CHECK (approval_mode IN ('MANUAL', 'AUTO')),
    ADD CONSTRAINT iam_ticket_approver_ids_array_check
        CHECK (jsonb_typeof(approver_ids) = 'array');

UPDATE iam_ticket AS ticket
SET approver_ids = COALESCE((
    SELECT jsonb_agg(approval.approver ORDER BY approval.approver)
    FROM ticket_approval AS approval
    WHERE approval.ticket_id = ticket.id
), '[]'::jsonb);

ALTER TABLE ticket_approval
    ALTER COLUMN approval_result DROP NOT NULL,
    ADD CONSTRAINT ticket_approval_result_check
        CHECK (approval_result IS NULL OR approval_result IN ('APPROVE', 'REJECT'));

CREATE UNIQUE INDEX ticket_approval_ticket_approver_unique
    ON ticket_approval (ticket_id, approver);

CREATE OR REPLACE FUNCTION prevent_iam_ticket_request_mutation()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.ticket_type IS DISTINCT FROM NEW.ticket_type
       OR OLD.account_id IS DISTINCT FROM NEW.account_id
       OR OLD.principal_name IS DISTINCT FROM NEW.principal_name
       OR OLD.request_policy IS DISTINCT FROM NEW.request_policy
       OR OLD.approval_mode IS DISTINCT FROM NEW.approval_mode
       OR OLD.approver_ids IS DISTINCT FROM NEW.approver_ids THEN
        RAISE EXCEPTION 'IAM ticket request and approvers are immutable; create a new ticket';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER iam_ticket_request_immutable
    BEFORE UPDATE ON iam_ticket
    FOR EACH ROW
    EXECUTE FUNCTION prevent_iam_ticket_request_mutation();
