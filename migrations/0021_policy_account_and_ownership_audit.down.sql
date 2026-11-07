ALTER TABLE iam_policy DROP COLUMN IF EXISTS managed_by_reviewed_by;
ALTER TABLE iam_policy DROP COLUMN IF EXISTS managed_by_reviewed_at;
ALTER TABLE iam_group DROP COLUMN IF EXISTS managed_by_reviewed_by;
ALTER TABLE iam_group DROP COLUMN IF EXISTS managed_by_reviewed_at;
ALTER TABLE iam_principal DROP COLUMN IF EXISTS managed_by_reviewed_by;
ALTER TABLE iam_principal DROP COLUMN IF EXISTS managed_by_reviewed_at;

DROP INDEX IF EXISTS iam_policy_account_idx;
ALTER TABLE iam_policy DROP COLUMN IF EXISTS account_id;
