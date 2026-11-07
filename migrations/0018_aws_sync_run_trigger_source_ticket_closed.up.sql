-- 0018: allow sync runs triggered by an auto-closed ticket.
-- The gitstatus worker closes a ticket only after the merge request is merged
-- AND CI succeeded (the apply really ran), so the account inventory can be
-- refreshed immediately instead of waiting for the scheduled sync.
-- The CHECK added inline in 0013 is named aws_sync_run_trigger_source_check.
ALTER TABLE aws_sync_run DROP CONSTRAINT aws_sync_run_trigger_source_check;
ALTER TABLE aws_sync_run ADD CONSTRAINT aws_sync_run_trigger_source_check
    CHECK (trigger_source IN ('MANUAL', 'TICKET_CLOSED'));
