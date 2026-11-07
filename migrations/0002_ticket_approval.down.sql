DROP TRIGGER IF EXISTS iam_ticket_request_immutable ON iam_ticket;
DROP FUNCTION IF EXISTS prevent_iam_ticket_request_mutation();

DROP INDEX IF EXISTS ticket_approval_ticket_approver_unique;
ALTER TABLE ticket_approval
    DROP CONSTRAINT IF EXISTS ticket_approval_result_check;

ALTER TABLE iam_ticket
    DROP CONSTRAINT IF EXISTS iam_ticket_approver_ids_array_check,
    DROP CONSTRAINT IF EXISTS iam_ticket_approval_mode_check,
    DROP COLUMN IF EXISTS approver_ids,
    DROP COLUMN IF EXISTS approval_mode;

DROP TABLE IF EXISTS aws_account_approver;
DROP TABLE IF EXISTS platform_user;
