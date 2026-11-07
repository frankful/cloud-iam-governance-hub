-- 0039: sync-run priority preemption (sync-priority design, 2026-11-05).
-- Priority: MANUAL (0) > TICKET_CLOSED (1) > SCHEDULED (2, reserved).
-- A higher-priority trigger supersedes a PENDING run of lower priority:
-- the pending row is marked SUPERSEDED (kept for history) and the new run
-- is enqueued immediately. RUNNING runs are never preempted.
-- The inline CHECK added in 0013 is named aws_sync_run_status_check.
ALTER TABLE aws_sync_run DROP CONSTRAINT aws_sync_run_status_check;
ALTER TABLE aws_sync_run ADD CONSTRAINT aws_sync_run_status_check
    CHECK (status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'SUPERSEDED'));
