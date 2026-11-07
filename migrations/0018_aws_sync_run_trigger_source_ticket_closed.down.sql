ALTER TABLE aws_sync_run DROP CONSTRAINT aws_sync_run_trigger_source_check;
UPDATE aws_sync_run SET trigger_source = 'MANUAL' WHERE trigger_source = 'TICKET_CLOSED';
ALTER TABLE aws_sync_run ADD CONSTRAINT aws_sync_run_trigger_source_check
    CHECK (trigger_source IN ('MANUAL'));
