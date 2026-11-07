package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRunRequiresDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	err := run(nil, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "database URL is required") {
		t.Fatalf("run() error = %v, want missing database URL", err)
	}
}

func TestRunRejectsNegativeLimit(t *testing.T) {
	err := run([]string{"-database-url", "postgres://unused", "-limit", "-1"},
		&bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "non-negative") {
		t.Fatalf("run() error = %v, want non-negative validation", err)
	}
}

func TestTranslationResultJSONShape(t *testing.T) {
	result := translationResult{
		PolicyID: 19, ParseStatus: "partial", ParseMessage: "unsupported operator",
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if decoded["policy_id"] != float64(19) || decoded["parse_status"] != "partial" ||
		decoded["parse_msg"] != "unsupported operator" {
		t.Fatalf("unexpected translation result JSON: %s", encoded)
	}
}
