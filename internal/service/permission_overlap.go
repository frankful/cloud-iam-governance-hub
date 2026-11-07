package service

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type ExistingIAMPolicy struct {
	Name     string
	Document json.RawMessage
}

type PermissionOverlapFinding struct {
	Action          string `json:"action"`
	Resource        string `json:"resource"`
	ExistingPolicy  string `json:"existing_policy"`
	MatchedAction   string `json:"matched_action"`
	MatchedResource string `json:"matched_resource"`
}

type namedPolicyStatements struct {
	name       string
	statements []iamPolicyStatement
}

// DetectPermissionOverlaps reports possible action/resource overlap with
// unconditional Allow statements already attached to a principal.
func DetectPermissionOverlaps(
	candidateDocument json.RawMessage,
	existingPolicies []ExistingIAMPolicy,
) ([]PermissionOverlapFinding, error) {
	var candidateDocumentShape iamPolicyDocument
	if err := json.Unmarshal(candidateDocument, &candidateDocumentShape); err != nil {
		return nil, fmt.Errorf("decode candidate policy: %w", err)
	}
	candidateStatements, err := decodePolicyStatements(candidateDocumentShape.Statement)
	if err != nil {
		return nil, fmt.Errorf("decode candidate policy statements: %w", err)
	}

	policies := make([]namedPolicyStatements, 0, len(existingPolicies))
	for policyIndex, policy := range existingPolicies {
		var document iamPolicyDocument
		if err := json.Unmarshal(policy.Document, &document); err != nil {
			return nil, fmt.Errorf("decode existing policy %q: %w", policy.Name, err)
		}
		statements, err := decodePolicyStatements(document.Statement)
		if err != nil {
			return nil, fmt.Errorf("decode existing policy %q statements: %w", policy.Name, err)
		}
		name := policy.Name
		if name == "" {
			name = fmt.Sprintf("policy[%d]", policyIndex)
		}
		policies = append(policies, namedPolicyStatements{name: name, statements: statements})
	}

	findings := make([]PermissionOverlapFinding, 0)
	seen := make(map[string]struct{})
	for _, candidateStatement := range candidateStatements {
		if !strings.EqualFold(strings.TrimSpace(candidateStatement.Effect), "Allow") ||
			hasPolicyCondition(candidateStatement.Condition) {
			continue
		}
		for _, candidateAction := range candidateStatement.Action {
			for _, candidateResource := range candidateStatement.Resource {
				for _, policy := range policies {
					for _, statement := range policy.statements {
						if !strings.EqualFold(strings.TrimSpace(statement.Effect), "Allow") ||
							hasPolicyCondition(statement.Condition) {
							continue
						}
						for _, actionPattern := range statement.Action {
							actionMatches, err := awsPolicyPatternMatches(actionPattern, candidateAction, true)
							if err != nil {
								return nil, fmt.Errorf("invalid action pattern in existing policy %q: %w", policy.name, err)
							}
							if !actionMatches {
								continue
							}
							for _, resourcePattern := range statement.Resource {
								resourceMatches, err := awsPolicyPatternMatches(resourcePattern, candidateResource, false)
								if err != nil {
									return nil, fmt.Errorf("invalid resource pattern in existing policy %q: %w", policy.name, err)
								}
								if !resourceMatches {
									continue
								}
								finding := PermissionOverlapFinding{
									Action: candidateAction, Resource: candidateResource,
									ExistingPolicy: policy.name, MatchedAction: actionPattern,
									MatchedResource: resourcePattern,
								}
								key := strings.Join([]string{
									finding.Action, finding.Resource, finding.ExistingPolicy,
									finding.MatchedAction, finding.MatchedResource,
								}, "\x00")
								if _, exists := seen[key]; exists {
									continue
								}
								seen[key] = struct{}{}
								findings = append(findings, finding)
							}
						}
					}
				}
			}
		}
	}
	return findings, nil
}

func hasPolicyCondition(condition json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(condition))
	return trimmed != "" && trimmed != "null" && trimmed != "{}"
}

func awsPolicyPatternMatches(pattern, value string, caseInsensitive bool) (bool, error) {
	var expression strings.Builder
	expression.WriteString("^")
	if caseInsensitive {
		expression.WriteString("(?i)")
	}
	for _, character := range pattern {
		switch character {
		case '*':
			expression.WriteString(".*")
		case '?':
			expression.WriteByte('.')
		default:
			expression.WriteString(regexp.QuoteMeta(string(character)))
		}
	}
	expression.WriteString("$")
	compiled, err := regexp.Compile(expression.String())
	if err != nil {
		return false, err
	}
	return compiled.MatchString(value), nil
}
