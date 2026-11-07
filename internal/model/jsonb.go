package model

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// JSONB stores a JSON value in a PostgreSQL JSONB column.
type JSONB json.RawMessage

// MarshalJSON preserves the stored value as JSON instead of encoding it as base64.
func (value JSONB) MarshalJSON() ([]byte, error) {
	if value == nil {
		return []byte("null"), nil
	}
	if !json.Valid(value) {
		return nil, fmt.Errorf("invalid JSONB value")
	}
	return value, nil
}

// UnmarshalJSON validates and stores a JSON value.
func (value *JSONB) UnmarshalJSON(data []byte) error {
	if !json.Valid(data) {
		return fmt.Errorf("invalid JSONB value")
	}
	*value = append((*value)[:0], data...)
	return nil
}

// Value implements driver.Valuer.
func (value JSONB) Value() (driver.Value, error) {
	if value == nil {
		return nil, nil
	}
	if !json.Valid(value) {
		return nil, fmt.Errorf("invalid JSONB value")
	}
	return []byte(value), nil
}

// Scan implements sql.Scanner.
func (value *JSONB) Scan(source interface{}) error {
	if source == nil {
		*value = nil
		return nil
	}

	var data []byte
	switch source := source.(type) {
	case []byte:
		data = source
	case string:
		data = []byte(source)
	default:
		return fmt.Errorf("cannot scan %T into JSONB", source)
	}

	if !json.Valid(data) {
		return fmt.Errorf("database returned invalid JSONB value")
	}

	*value = append((*value)[:0], data...)
	return nil
}

// GormDataType identifies JSONB values as JSON to GORM.
func (JSONB) GormDataType() string {
	return "json"
}
