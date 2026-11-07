package model

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestJSONBValueAndScan(t *testing.T) {
	original := JSONB(`{"enabled":true}`)

	value, err := original.Value()
	if err != nil {
		t.Fatalf("Value() error = %v", err)
	}

	var scanned JSONB
	if err := scanned.Scan(value); err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !bytes.Equal(scanned, original) {
		t.Fatalf("Scan() = %s, want %s", scanned, original)
	}
}

func TestJSONBRejectsInvalidJSON(t *testing.T) {
	if _, err := JSONB(`{invalid}`).Value(); err == nil {
		t.Fatal("Value() expected invalid JSON error")
	}

	var scanned JSONB
	if err := scanned.Scan([]byte(`{invalid}`)); err == nil {
		t.Fatal("Scan() expected invalid JSON error")
	}
}

func TestJSONBScansSQLNull(t *testing.T) {
	value := JSONB(`{"old":true}`)
	if err := value.Scan(nil); err != nil {
		t.Fatalf("Scan(nil) error = %v", err)
	}
	if value != nil {
		t.Fatalf("Scan(nil) = %s, want nil", value)
	}
}

func TestJSONBJSONSerialization(t *testing.T) {
	value := JSONB(`{"enabled":true}`)

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if string(data) != `{"enabled":true}` {
		t.Fatalf("Marshal() = %s, want embedded JSON object", data)
	}

	var decoded JSONB
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !bytes.Equal(decoded, value) {
		t.Fatalf("Unmarshal() = %s, want %s", decoded, value)
	}
}
