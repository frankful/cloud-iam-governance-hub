DROP TRIGGER IF EXISTS iam_baseline_job_identity_immutable ON iam_baseline_job;
DROP FUNCTION IF EXISTS prevent_iam_baseline_job_identity_mutation();
DROP INDEX IF EXISTS iam_baseline_job_account_created_idx;
DROP TABLE IF EXISTS iam_baseline_job;
