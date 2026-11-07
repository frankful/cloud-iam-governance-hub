package abstractiam

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestAbstractPolicyJSONRoundTrip(t *testing.T) {
	policy := AbstractPolicy{
		ID:          "policy-1",
		Name:        "reports-reader",
		Description: "Read report objects",
		Statements: []AbstractStatement{{
			Effect:       "Allow",
			Actions:      []string{"s3:GetObject"},
			Resources:    []string{"//storage/bucket/reports/*"},
			NotActions:   []string{"iam:DeleteRole"},
			NotResources: []string{"//identity/role/admin"},
			Conditions: []AbstractCondition{{
				Key:      "aws:PrincipalOrgID",
				Operator: "StringEquals",
				Values:   []interface{}{"o-example", float64(7), true},
			}},
		}},
	}

	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var decoded AbstractPolicy
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !reflect.DeepEqual(decoded, policy) {
		t.Errorf("round-trip = %#v, want %#v", decoded, policy)
	}
}
