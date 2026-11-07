ALTER TABLE iam_baseline_publication
    DROP CONSTRAINT IF EXISTS iam_baseline_publication_published_identity;
ALTER TABLE iam_baseline_publication
    ADD CONSTRAINT iam_baseline_publication_published_identity CHECK (
        status <> 'PUBLISHED' OR (pull_request_url <> '' AND published_at IS NOT NULL)
    );
ALTER TABLE iam_baseline_publication
    DROP COLUMN IF EXISTS files;
