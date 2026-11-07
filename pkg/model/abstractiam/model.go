package abstractiam

// AbstractPolicy is a cloud-neutral IAM policy representation. Actions and
// resources use the platform DSL and are not tied to an AWS document format.
type AbstractPolicy struct {
	ID          string              `json:"id,omitempty"`
	Name        string              `json:"name,omitempty"`
	Description string              `json:"description,omitempty"`
	Statements  []AbstractStatement `json:"statements"`
}

// AbstractStatement describes one allow/deny rule in the neutral policy DSL.
type AbstractStatement struct {
	Effect       string              `json:"effect"`
	Actions      []string            `json:"actions,omitempty"`
	Resources    []string            `json:"resources,omitempty"`
	NotActions   []string            `json:"not_actions,omitempty"`
	NotResources []string            `json:"not_resources,omitempty"`
	Conditions   []AbstractCondition `json:"conditions,omitempty"`
}

// AbstractCondition is a best-effort normalized policy condition.
type AbstractCondition struct {
	Key      string        `json:"key"`
	Operator string        `json:"operator"`
	Values   []interface{} `json:"values"`
}
