package repo

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/frankful/cloud-iam-governance-hub/pkg/model/abstractiam"
)

type fakePolicyTranslator struct {
	policy  *abstractiam.AbstractPolicy
	status  string
	message string
	err     error
}

func (translator fakePolicyTranslator) FromCloudPolicy(json.RawMessage) (*abstractiam.AbstractPolicy, string, string, error) {
	return translator.policy, translator.status, translator.message, translator.err
}

func TestTranslateAndSaveRequiresDatabase(t *testing.T) {
	status, message, err := TranslateAndSaveAbstractPolicySnapshot(
		context.Background(), nil,
		fakePolicyTranslator{status: "success", policy: &abstractiam.AbstractPolicy{}},
		1, "arn:aws:iam::123456789012:policy/test", json.RawMessage(`{}`),
	)
	if err == nil || status != "success" || message != "" {
		t.Fatalf("status/message/error = %q/%q/%v", status, message, err)
	}
}

func TestTranslateAndSaveRejectsMissingTranslator(t *testing.T) {
	_, _, err := TranslateAndSaveAbstractPolicySnapshot(
		context.Background(), nil, nil, 1, "", json.RawMessage(`{}`),
	)
	if err == nil || !strings.Contains(err.Error(), "translator must not be nil") {
		t.Fatalf("error = %v", err)
	}
}
