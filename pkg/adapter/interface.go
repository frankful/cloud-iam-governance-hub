package adapter

import (
	"context"
	"encoding/json"

	"github.com/frankful/cloud-iam-governance-hub/pkg/model/abstractiam"
)

// CloudIAMSnapshot is the cloud-neutral boundary for an already implemented
// provider inventory fetcher. Raw entity payloads remain lossless.
type CloudIAMSnapshot struct {
	Provider    string            `json:"provider"`
	RawEntities []json.RawMessage `json:"raw_entities"`
}

// CloudAdapter provides provider connectivity, inventory, and policy
// translation capabilities.
type CloudAdapter interface {
	TestConnect(ctx context.Context) error
	FetchIAMSnapshot(ctx context.Context) (*CloudIAMSnapshot, error)
	FromCloudPolicy(rawPolicyJSON json.RawMessage) (*abstractiam.AbstractPolicy, string, string, error)
	ToCloudPolicy(policy *abstractiam.AbstractPolicy) (json.RawMessage, error)
}
