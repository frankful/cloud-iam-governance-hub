-- Collapse SUPERSEDED rows back to FAILED (they never produced a diff),
-- then restore the 0013 constraint.
UPDATE aws_sync_run SET status = 'FAILED',
    last_error = COALESCE(last_error, 'superseded by a higher-priority sync trigger')
WHERE status = 'SUPERSEDED';
ALTER TABLE aws_sync_run DROP CONSTRAINT aws_sync_run_status_check;
ALTER TABLE aws_sync_run ADD CONSTRAINT aws_sync_run_status_check
    CHECK (status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED'));
