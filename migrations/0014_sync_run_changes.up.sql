-- 0014: per-run inventory diff for AWS account synchronization.
-- The collector snapshots the platform inventory before SaveAccountIAM
-- overwrites it, computes added/removed principals and groups, and stores
-- the result here so operators can download it after each run.
ALTER TABLE aws_sync_run ADD COLUMN changes JSONB;
