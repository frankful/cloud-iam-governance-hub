package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPlatformTokenNeverSerializesTokenHash(t *testing.T) {
	token := PlatformToken{
		ID:          1,
		UserID:      "alice",
		TokenHash:   []byte("private-digest"),
		TokenPrefix: "iamg_abcd",
		TokenName:   "automation",
		CreatedAt:   time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC),
	}
	encoded, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.Contains(string(encoded), "private-digest") ||
		strings.Contains(string(encoded), "token_hash") {
		t.Fatalf("serialized token exposes digest: %s", encoded)
	}
	if !strings.Contains(string(encoded), `"token_prefix":"iamg_abcd"`) {
		t.Fatalf("serialized token omits lookup prefix: %s", encoded)
	}
}

func TestPhase1ModelsUseExpectedTables(t *testing.T) {
	tables := map[string]string{
		(PlatformRole{}).TableName():           "platform_role",
		(UserRoleMapping{}).TableName():        "user_role_mapping",
		(PlatformToken{}).TableName():          "platform_token",
		(AWSAccountConfig{}).TableName():       "aws_account_config",
		(IAMBaseline{}).TableName():            "iam_baseline",
		(TicketValidationRecord{}).TableName(): "ticket_validation_record",
		(IACExecutionRecord{}).TableName():     "iac_execution_record",
	}
	for actual, expected := range tables {
		if actual != expected {
			t.Errorf("TableName() = %q, want %q", actual, expected)
		}
	}
}
