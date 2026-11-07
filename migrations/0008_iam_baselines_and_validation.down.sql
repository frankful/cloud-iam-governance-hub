DROP TRIGGER IF EXISTS ticket_validation_record_append_only ON ticket_validation_record;
DROP FUNCTION IF EXISTS prevent_ticket_validation_mutation();
DROP TABLE IF EXISTS ticket_validation_record;
DROP TRIGGER IF EXISTS iam_baseline_content_immutable ON iam_baseline;
DROP FUNCTION IF EXISTS prevent_iam_baseline_content_mutation();
DROP TABLE IF EXISTS iam_baseline;
