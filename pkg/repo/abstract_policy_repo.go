package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/frankful/cloud-iam-governance-hub/pkg/model/abstractiam"
)

var validParseStatuses = map[string]struct{}{
	"success": {}, "partial": {}, "failed": {},
}

// SaveAbstractPolicySnapshot stores the best-effort neutral policy alongside
// its immutable raw snapshot row. db is supplied because this repository has
// no package-global database handle.
func SaveAbstractPolicySnapshot(
	ctx context.Context,
	db *sql.DB,
	snapshotID int64,
	policy *abstractiam.AbstractPolicy,
	parseStatus string,
	parseMessage string,
	sourceEntityARN ...string,
) error {
	if db == nil {
		return errors.New("database connection must not be nil")
	}
	if snapshotID <= 0 {
		return errors.New("cloud IAM snapshot ID must be positive")
	}
	if _, ok := validParseStatuses[parseStatus]; !ok {
		return fmt.Errorf("unsupported abstract policy parse status %q", parseStatus)
	}
	if len(sourceEntityARN) > 1 {
		return errors.New("at most one source entity ARN may be provided")
	}
	var sourceARN interface{}
	if len(sourceEntityARN) == 1 && sourceEntityARN[0] != "" {
		sourceARN = sourceEntityARN[0]
	} else if policy != nil && policy.ID != "" {
		sourceARN = policy.ID
	}
	var payload interface{}
	if policy != nil {
		encoded, err := json.Marshal(policy)
		if err != nil {
			return fmt.Errorf("marshal abstract policy: %w", err)
		}
		payload = string(encoded)
	} else {
		payload = "null"
	}
	_, err := db.ExecContext(ctx, `INSERT INTO abstract_policy_snapshot
		(cloud_iam_snapshot_id, source_entity_arn, abstract_payload, parse_status, parse_msg)
		VALUES ($1, $2, $3::jsonb, $4, NULLIF($5, ''))`,
		snapshotID, sourceARN, payload, parseStatus, parseMessage,
	)
	if err != nil {
		return fmt.Errorf("save abstract policy snapshot %d: %w", snapshotID, err)
	}
	return nil
}

// TranslateAndSaveAbstractPolicySnapshot is the non-blocking parser hook for a
// snapshot pipeline. Parse failures are recorded as failed rows; only a
// persistence error is returned to the caller.
func TranslateAndSaveAbstractPolicySnapshot(
	ctx context.Context,
	db *sql.DB,
	translator interface {
		FromCloudPolicy(json.RawMessage) (*abstractiam.AbstractPolicy, string, string, error)
	},
	snapshotID int64,
	sourceEntityARN string,
	rawPolicyJSON json.RawMessage,
) (string, string, error) {
	if translator == nil {
		return "", "", errors.New("cloud policy translator must not be nil")
	}
	policy, status, message, parseErr := translator.FromCloudPolicy(rawPolicyJSON)
	if parseErr != nil {
		status = "failed"
		if message == "" {
			message = parseErr.Error()
		}
	}
	if status == "" {
		status = "failed"
		message = "translator returned an empty parse status"
		policy = nil
	}
	if err := SaveAbstractPolicySnapshot(ctx, db, snapshotID, policy, status, message, sourceEntityARN); err != nil {
		return status, message, err
	}
	return status, message, nil
}
