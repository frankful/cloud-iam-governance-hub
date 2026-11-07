DROP INDEX IF EXISTS idx_iam_identity_provider_account_live;
DROP TABLE IF EXISTS iam_identity_provider;

DROP INDEX IF EXISTS idx_iam_instance_profile_account_live;
DROP TABLE IF EXISTS iam_instance_profile;

ALTER TABLE iam_principal
    DROP COLUMN IF EXISTS permissions_boundary_type,
    DROP COLUMN IF EXISTS permissions_boundary_arn,
    DROP COLUMN IF EXISTS path;
