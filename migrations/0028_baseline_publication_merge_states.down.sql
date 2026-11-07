ALTER TABLE iam_baseline_publication
    DROP CONSTRAINT iam_baseline_publication_status_check;

ALTER TABLE iam_baseline_publication
    ADD CONSTRAINT iam_baseline_publication_status_check
    CHECK (status IN ('PUBLISHING', 'PUBLISHED', 'FAILED'));
