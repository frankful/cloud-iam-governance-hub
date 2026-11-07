package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	cloudadapter "github.com/frankful/cloud-iam-governance-hub/pkg/adapter"
	"github.com/frankful/cloud-iam-governance-hub/pkg/model/abstractiam"
)

const (
	ParseStatusSuccess = "success"
	ParseStatusPartial = "partial"
	ParseStatusFailed  = "failed"
)

var supportedConditionOperators = map[string]struct{}{
	"StringEquals": {}, "StringNotEquals": {}, "StringEqualsIgnoreCase": {},
	"StringNotEqualsIgnoreCase": {}, "StringLike": {}, "StringNotLike": {},
	"NumericEquals": {}, "NumericNotEquals": {}, "NumericLessThan": {},
	"NumericLessThanEquals": {}, "NumericGreaterThan": {}, "NumericGreaterThanEquals": {},
	"DateEquals": {}, "DateNotEquals": {}, "DateLessThan": {}, "DateLessThanEquals": {},
	"DateGreaterThan": {}, "DateGreaterThanEquals": {}, "Bool": {},
	"ArnEquals": {}, "ArnLike": {}, "ArnNotEquals": {}, "ArnNotLike": {},
	"Null": {},
}

func isSupportedConditionOperator(operator string) bool {
	base := operator
	if strings.HasPrefix(base, "ForAnyValue:") {
		base = strings.TrimPrefix(base, "ForAnyValue:")
	} else if strings.HasPrefix(base, "ForAllValues:") {
		base = strings.TrimPrefix(base, "ForAllValues:")
	}
	base = strings.TrimSuffix(base, "IfExists")
	_, ok := supportedConditionOperators[base]
	return ok
}

type ConnectFunc func(context.Context) error
type SnapshotFetchFunc func(context.Context) (*cloudadapter.CloudIAMSnapshot, error)

// AwsAdapter implements AWS policy conversion. Existing AWS connection and
// inventory implementations are injected so this adapter does not duplicate
// their responsibilities.
type AwsAdapter struct {
	testConnect      ConnectFunc
	fetchIAMSnapshot SnapshotFetchFunc
}

func NewAwsAdapter(testConnect ConnectFunc, fetchIAMSnapshot SnapshotFetchFunc) *AwsAdapter {
	return &AwsAdapter{testConnect: testConnect, fetchIAMSnapshot: fetchIAMSnapshot}
}

func (adapter *AwsAdapter) TestConnect(ctx context.Context) error {
	if adapter == nil || adapter.testConnect == nil {
		return errors.New("AWS connectivity test implementation is not configured")
	}
	return adapter.testConnect(ctx)
}

func (adapter *AwsAdapter) FetchIAMSnapshot(ctx context.Context) (*cloudadapter.CloudIAMSnapshot, error) {
	if adapter == nil || adapter.fetchIAMSnapshot == nil {
		return nil, errors.New("existing AWS IAM snapshot fetcher is not configured")
	}
	snapshot, err := adapter.fetchIAMSnapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch AWS IAM snapshot: %w", err)
	}
	if snapshot == nil {
		return nil, errors.New("AWS IAM snapshot fetcher returned nil")
	}
	if snapshot.Provider == "" {
		snapshot.Provider = "aws"
	}
	return snapshot, nil
}

type awsPolicyDocument struct {
	Version      string          `json:"Version,omitempty"`
	ID           string          `json:"Id,omitempty"`
	Name         string          `json:"Name,omitempty"`
	Description  string          `json:"Description,omitempty"`
	Statement    json.RawMessage `json:"Statement"`
	Principal    json.RawMessage `json:"Principal,omitempty"`
	NotPrincipal json.RawMessage `json:"NotPrincipal,omitempty"`
}

type awsPolicyStatement struct {
	Sid          string                            `json:"Sid,omitempty"`
	Effect       string                            `json:"Effect"`
	Action       stringList                        `json:"Action,omitempty"`
	Resource     stringList                        `json:"Resource,omitempty"`
	NotAction    stringList                        `json:"NotAction,omitempty"`
	NotResource  stringList                        `json:"NotResource,omitempty"`
	Principal    json.RawMessage                   `json:"Principal,omitempty"`
	NotPrincipal json.RawMessage                   `json:"NotPrincipal,omitempty"`
	Condition    map[string]map[string]interface{} `json:"Condition,omitempty"`
}

type stringList []string

func (values *stringList) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*values = []string{single}
		return nil
	}
	var multiple []string
	if err := json.Unmarshal(data, &multiple); err != nil {
		return fmt.Errorf("expected string or array of strings: %w", err)
	}
	*values = multiple
	return nil
}

// FromCloudPolicy converts a best-effort AWS policy document to the neutral
// policy DSL. The original AWS JSON remains owned by the snapshot pipeline.
func (adapter *AwsAdapter) FromCloudPolicy(
	rawPolicyJSON json.RawMessage,
) (*abstractiam.AbstractPolicy, string, string, error) {
	partial := make(map[string]struct{})
	var document awsPolicyDocument
	if len(rawPolicyJSON) == 0 || !json.Valid(rawPolicyJSON) {
		err := errors.New("AWS policy document is empty or invalid JSON")
		return nil, ParseStatusFailed, err.Error(), err
	}
	if err := json.Unmarshal(rawPolicyJSON, &document); err != nil {
		return nil, ParseStatusFailed, err.Error(), err
	}
	if len(document.Principal) > 0 || len(document.NotPrincipal) > 0 {
		partial["Principal field is not included in the abstract DSL"] = struct{}{}
	}
	statements, err := decodeAWSStatements(document.Statement)
	if err != nil {
		return nil, ParseStatusFailed, err.Error(), err
	}

	policy := &abstractiam.AbstractPolicy{
		ID:          document.ID,
		Name:        document.Name,
		Description: document.Description,
		Statements:  make([]abstractiam.AbstractStatement, 0, len(statements)),
	}
	for index, statement := range statements {
		if len(statement.Principal) > 0 || len(statement.NotPrincipal) > 0 {
			partial["Principal field is not included in the abstract DSL"] = struct{}{}
		}
		abstractStatement := abstractiam.AbstractStatement{
			Effect:       statement.Effect,
			Actions:      append([]string(nil), statement.Action...),
			Resources:    append([]string(nil), statement.Resource...),
			NotActions:   append([]string(nil), statement.NotAction...),
			NotResources: append([]string(nil), statement.NotResource...),
		}
		operators := make([]string, 0, len(statement.Condition))
		for operator := range statement.Condition {
			operators = append(operators, operator)
		}
		sort.Strings(operators)
		for _, operator := range operators {
			keys := statement.Condition[operator]
			if !isSupportedConditionOperator(operator) {
				partial[fmt.Sprintf("unsupported AWS condition operator %q in statement %d", operator, index)] = struct{}{}
				continue
			}
			conditionKeys := make([]string, 0, len(keys))
			for key := range keys {
				conditionKeys = append(conditionKeys, key)
			}
			sort.Strings(conditionKeys)
			for _, key := range conditionKeys {
				values, err := conditionValues(keys[key])
				if err != nil {
					partial[fmt.Sprintf("condition %q for key %q could not be normalized: %v", operator, key, err)] = struct{}{}
					continue
				}
				abstractStatement.Conditions = append(abstractStatement.Conditions, abstractiam.AbstractCondition{
					Key: key, Operator: operator, Values: values,
				})
			}
		}
		policy.Statements = append(policy.Statements, abstractStatement)
	}
	if len(partial) == 0 {
		return policy, ParseStatusSuccess, "", nil
	}
	warnings := make([]string, 0, len(partial))
	for warning := range partial {
		warnings = append(warnings, warning)
	}
	sort.Strings(warnings)
	return policy, ParseStatusPartial, strings.Join(warnings, "; "), nil
}

func decodeAWSStatements(raw json.RawMessage) ([]awsPolicyStatement, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, errors.New("AWS policy document has no Statement")
	}
	var statements []awsPolicyStatement
	if err := json.Unmarshal(raw, &statements); err == nil {
		return statements, nil
	}
	var statement awsPolicyStatement
	if err := json.Unmarshal(raw, &statement); err != nil {
		return nil, fmt.Errorf("decode AWS policy Statement: %w", err)
	}
	return []awsPolicyStatement{statement}, nil
}

func conditionValues(value interface{}) ([]interface{}, error) {
	switch value := value.(type) {
	case []interface{}:
		return value, nil
	case string, float64, bool, nil:
		return []interface{}{value}, nil
	default:
		return nil, fmt.Errorf("unsupported value type %T", value)
	}
}

// ToCloudPolicy converts the neutral DSL to an AWS IAM policy document.
func (adapter *AwsAdapter) ToCloudPolicy(policy *abstractiam.AbstractPolicy) (json.RawMessage, error) {
	if policy == nil {
		return nil, errors.New("abstract policy must not be nil")
	}
	if len(policy.Statements) == 0 {
		return nil, errors.New("abstract policy must contain at least one statement")
	}
	statements := make([]map[string]interface{}, 0, len(policy.Statements))
	for index, abstractStatement := range policy.Statements {
		if abstractStatement.Effect != "Allow" && abstractStatement.Effect != "Deny" {
			return nil, fmt.Errorf("statement %d has unsupported effect %q", index, abstractStatement.Effect)
		}
		statement := map[string]interface{}{"Effect": abstractStatement.Effect}
		if len(abstractStatement.Actions) > 0 {
			statement["Action"] = normalizeSingleOrMultiple(abstractStatement.Actions)
		}
		if len(abstractStatement.Resources) > 0 {
			statement["Resource"] = normalizeSingleOrMultiple(abstractStatement.Resources)
		}
		if len(abstractStatement.NotActions) > 0 {
			statement["NotAction"] = normalizeSingleOrMultiple(abstractStatement.NotActions)
		}
		if len(abstractStatement.NotResources) > 0 {
			statement["NotResource"] = normalizeSingleOrMultiple(abstractStatement.NotResources)
		}
		if len(abstractStatement.Actions)+len(abstractStatement.NotActions) == 0 {
			return nil, fmt.Errorf("statement %d must contain Action or NotAction", index)
		}
		if len(abstractStatement.Resources)+len(abstractStatement.NotResources) == 0 {
			return nil, fmt.Errorf("statement %d must contain Resource or NotResource", index)
		}
		conditions, err := encodeConditions(abstractStatement.Conditions)
		if err != nil {
			return nil, fmt.Errorf("statement %d: %w", index, err)
		}
		if len(conditions) > 0 {
			statement["Condition"] = conditions
		}
		statements = append(statements, statement)
	}
	document := map[string]interface{}{
		"Version":   "2012-10-17",
		"Statement": statements,
	}
	if policy.ID != "" {
		document["Id"] = policy.ID
	}
	return json.Marshal(document)
}

func normalizeSingleOrMultiple(values []string) interface{} {
	if len(values) == 1 {
		return values[0]
	}
	return values
}

func encodeConditions(conditions []abstractiam.AbstractCondition) (map[string]map[string]interface{}, error) {
	if len(conditions) == 0 {
		return nil, nil
	}
	result := make(map[string]map[string]interface{})
	for _, condition := range conditions {
		if !isSupportedConditionOperator(condition.Operator) {
			return nil, fmt.Errorf("unsupported AWS condition operator %q", condition.Operator)
		}
		if strings.TrimSpace(condition.Key) == "" {
			return nil, errors.New("condition key must not be empty")
		}
		if len(condition.Values) == 0 {
			return nil, fmt.Errorf("condition %q has no values", condition.Key)
		}
		operatorConditions := result[condition.Operator]
		if operatorConditions == nil {
			operatorConditions = make(map[string]interface{})
			result[condition.Operator] = operatorConditions
		}
		if _, exists := operatorConditions[condition.Key]; exists {
			return nil, fmt.Errorf("duplicate condition %q for operator %q", condition.Key, condition.Operator)
		}
		if len(condition.Values) == 1 {
			operatorConditions[condition.Key] = condition.Values[0]
		} else {
			operatorConditions[condition.Key] = condition.Values
		}
	}
	return result, nil
}

var _ cloudadapter.CloudAdapter = (*AwsAdapter)(nil)
