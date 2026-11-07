DROP TRIGGER IF EXISTS iac_execution_record_append_only ON iac_execution_record;
DROP FUNCTION IF EXISTS prevent_iac_execution_mutation();
DROP TABLE IF EXISTS iac_execution_record;
