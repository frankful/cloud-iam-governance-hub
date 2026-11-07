DROP TRIGGER IF EXISTS iam_audit_event_append_only ON iam_audit_event;
DROP FUNCTION IF EXISTS prevent_iam_audit_event_mutation();
DROP TABLE IF EXISTS iam_audit_event;
