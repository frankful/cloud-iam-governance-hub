// Package githost provides a provider-neutral interface for Git hosting
// services (GitLab, GitHub). It abstracts merge request/pull request
// status polling and CI/CD pipeline status retrieval.
package githost

import (
	"context"
	"fmt"
	"time"
)

// MergeState represents the state of a merge request or pull request.
type MergeState string

const (
	MergeStateOpen    MergeState = "OPEN"
	MergeStateMerged  MergeState = "MERGED"
	MergeStateClosed  MergeState = "CLOSED"
	MergeStateUnknown MergeState = "UNKNOWN"
)

// CIState represents the state of a CI/CD pipeline or check run.
type CIState string

const (
	CIStatePending   CIState = "PENDING"
	CIStateRunning   CIState = "RUNNING"
	CIStateSucceeded CIState = "SUCCEEDED"
	CIStateFailed    CIState = "FAILED"
	CIStateCanceled  CIState = "CANCELED"
	CIStateUnknown   CIState = "UNKNOWN"
)

// ApplyResult represents the result of a Terraform apply operation.
type ApplyResult string

const (
	ApplyResultPending   ApplyResult = "PENDING"
	ApplyResultSucceeded ApplyResult = "SUCCEEDED"
	ApplyResultFailed    ApplyResult = "FAILED"
	ApplyResultCanceled  ApplyResult = "CANCELED"
	ApplyResultUnknown   ApplyResult = "UNKNOWN"
)

// MergeRequestStatus represents the current status of a merge request or pull request.
type MergeRequestStatus struct {
	Number       string
	URL          string
	State        MergeState
	MergeCommit  string
	HeadSHA      string
	BaseBranch   string
	SourceBranch string
	Title        string
	UpdatedAt    time.Time
}

// PipelineStatus represents the current status of a CI/CD pipeline or check run.
type PipelineStatus struct {
	ID         string
	Name       string
	State      CIState
	CommitSHA  string
	StartedAt  *time.Time
	FinishedAt *time.Time
	WebURL     string
}

// GitHost provides a provider-neutral interface for Git hosting services.
// Implementations must be safe for concurrent use.
type GitHost interface {
	// FetchMergeRequest retrieves the current status of a merge request or pull request.
	// Returns nil if the request does not exist.
	FetchMergeRequest(ctx context.Context, project string, number string) (*MergeRequestStatus, error)

	// FetchPipelineStatus retrieves the current status of a CI/CD pipeline or check run.
	// Returns nil if the pipeline does not exist.
	FetchPipelineStatus(ctx context.Context, project string, pipelineID string) (*PipelineStatus, error)

	// FetchCommitStatuses retrieves the status of all check runs for a commit.
	FetchCommitStatuses(ctx context.Context, project string, commitSHA string) ([]PipelineStatus, error)
}

// MergeRequestMerger asks the provider to merge an already-approved request.
// Implementations must use the normal provider API so required approvals and
// branch protection remain authoritative; force/bypass options are forbidden.
type MergeRequestMerger interface {
	MergeMergeRequest(ctx context.Context, project, number string) error
}

// GitHostConfig contains configuration for creating a GitHost client.
type GitHostConfig struct {
	Provider      string // "gitlab" or "github"
	BaseURL       string
	Token         string
	ProjectID     string // GitLab project ID or GitHub "owner/repo"
	TargetBranch  string
	TerraformPath string
}

// NewGitHost creates a new GitHost client based on the provider configuration.
func NewGitHost(config GitHostConfig) (GitHost, error) {
	switch config.Provider {
	case "gitlab":
		return NewGitLabHost(config)
	case "github":
		return NewGitHubHost(config)
	default:
		return nil, fmt.Errorf("unsupported git provider: %s", config.Provider)
	}
}
