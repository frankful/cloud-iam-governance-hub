CREATE FUNCTION prevent_iam_ticket_snapshot_mutation()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.ticket_type IS DISTINCT FROM NEW.ticket_type
       OR OLD.account_id IS DISTINCT FROM NEW.account_id
       OR OLD.principal_name IS DISTINCT FROM NEW.principal_name
       OR OLD.request_policy IS DISTINCT FROM NEW.request_policy
       OR OLD.approval_mode IS DISTINCT FROM NEW.approval_mode
       OR OLD.approver_ids IS DISTINCT FROM NEW.approver_ids
       OR OLD.submitter IS DISTINCT FROM NEW.submitter
       OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION 'IAM ticket request and approver snapshots are immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER iam_ticket_snapshot_immutable
    BEFORE UPDATE ON iam_ticket
    FOR EACH ROW
    EXECUTE FUNCTION prevent_iam_ticket_snapshot_mutation();
