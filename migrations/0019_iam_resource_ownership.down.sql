DROP INDEX IF EXISTS iam_policy_managed_by_idx;
DROP INDEX IF EXISTS iam_principal_managed_by_idx;

ALTER TABLE iam_policy DROP CONSTRAINT IF EXISTS iam_policy_managed_by_check;
ALTER TABLE iam_policy DROP COLUMN IF EXISTS managed_by;

ALTER TABLE iam_group DROP CONSTRAINT IF EXISTS iam_group_managed_by_check;
ALTER TABLE iam_group DROP COLUMN IF EXISTS managed_by;

ALTER TABLE iam_principal DROP CONSTRAINT IF EXISTS iam_principal_managed_by_check;
ALTER TABLE iam_principal DROP COLUMN IF EXISTS managed_by;
