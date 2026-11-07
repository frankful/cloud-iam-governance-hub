package githost

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	gitlab "github.com/xanzy/go-gitlab"
)

// GitLabHost implements GitHost for GitLab.
type GitLabHost struct {
	client *gitlab.Client
	config GitHostConfig
}

// NewGitLabHost creates a new GitLab GitHost client.
func NewGitLabHost(config GitHostConfig) (*GitLabHost, error) {
	if config.Token == "" {
		return nil, fmt.Errorf("GitLab token must not be empty")
	}
	if config.ProjectID == "" {
		return nil, fmt.Errorf("GitLab project ID must not be empty")
	}

	options := []gitlab.ClientOptionFunc{
		gitlab.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
	}
	if config.BaseURL != "" {
		options = append(options, gitlab.WithBaseURL(config.BaseURL))
	}

	client, err := gitlab.NewClient(config.Token, options...)
	if err != nil {
		return nil, fmt.Errorf("create GitLab client: %w", err)
	}

	return &GitLabHost{
		client: client,
		config: config,
	}, nil
}

// FetchMergeRequest retrieves the current status of a GitLab merge request.
func (h *GitLabHost) FetchMergeRequest(ctx context.Context, project string, number string) (*MergeRequestStatus, error) {
	mrNumber, err := strconv.Atoi(number)
	if err != nil {
		return nil, fmt.Errorf("invalid merge request number %q: %w", number, err)
	}

	mr, _, err := h.client.MergeRequests.GetMergeRequest(project, mrNumber, nil, gitlab.WithContext(ctx))
	if err != nil {
		if isGitLabNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("fetch GitLab merge request: %w", err)
	}

	return &MergeRequestStatus{
		Number:       number,
		URL:          mr.WebURL,
		State:        mapGitLabMergeState(mr.State),
		MergeCommit:  mr.MergeCommitSHA,
		HeadSHA:      mr.SHA,
		BaseBranch:   mr.TargetBranch,
		SourceBranch: mr.SourceBranch,
		Title:        mr.Title,
		UpdatedAt:    time.Now(),
	}, nil
}

// FetchPipelineStatus retrieves the current status of a GitLab pipeline.
func (h *GitLabHost) FetchPipelineStatus(ctx context.Context, project string, pipelineID string) (*PipelineStatus, error) {
	pipelineNumber, err := strconv.Atoi(pipelineID)
	if err != nil {
		return nil, fmt.Errorf("invalid pipeline ID %q: %w", pipelineID, err)
	}

	pipeline, _, err := h.client.Pipelines.GetPipeline(project, pipelineNumber, gitlab.WithContext(ctx))
	if err != nil {
		if isGitLabNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("fetch GitLab pipeline: %w", err)
	}

	return &PipelineStatus{
		ID:        pipelineID,
		Name:      pipeline.Ref,
		State:     mapGitLabCIState(pipeline.Status),
		CommitSHA: pipeline.SHA,
		WebURL:    pipeline.WebURL,
	}, nil
}

// FetchCommitStatuses retrieves the status of all GitLab pipelines for a commit.
func (h *GitLabHost) FetchCommitStatuses(ctx context.Context, project string, commitSHA string) ([]PipelineStatus, error) {
	pipelines, _, err := h.client.Pipelines.ListProjectPipelines(project, &gitlab.ListProjectPipelinesOptions{
		SHA: gitlab.String(commitSHA),
	}, gitlab.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("list GitLab pipelines for commit: %w", err)
	}

	statuses := make([]PipelineStatus, 0, len(pipelines))
	for _, pipeline := range pipelines {
		statuses = append(statuses, PipelineStatus{
			ID:        strconv.Itoa(pipeline.ID),
			Name:      pipeline.Ref,
			State:     mapGitLabCIState(pipeline.Status),
			CommitSHA: pipeline.SHA,
			WebURL:    pipeline.WebURL,
		})
	}
	return statuses, nil
}

func (h *GitLabHost) MergeMergeRequest(ctx context.Context, project, number string) error {
	mrNumber, err := strconv.Atoi(number)
	if err != nil {
		return fmt.Errorf("invalid merge request number %q: %w", number, err)
	}
	mergeWhenPipelineSucceeds := false
	removeSourceBranch := false
	_, _, err = h.client.MergeRequests.AcceptMergeRequest(project, mrNumber, &gitlab.AcceptMergeRequestOptions{
		MergeWhenPipelineSucceeds: &mergeWhenPipelineSucceeds,
		ShouldRemoveSourceBranch:  &removeSourceBranch,
	}, gitlab.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("merge GitLab merge request: %w", err)
	}
	return nil
}

func mapGitLabMergeState(state string) MergeState {
	switch state {
	case "opened":
		return MergeStateOpen
	case "merged":
		return MergeStateMerged
	case "closed":
		return MergeStateClosed
	default:
		return MergeStateUnknown
	}
}

func mapGitLabCIState(status string) CIState {
	switch status {
	case "pending":
		return CIStatePending
	case "running":
		return CIStateRunning
	case "success":
		return CIStateSucceeded
	case "failed":
		return CIStateFailed
	case "canceled":
		return CIStateCanceled
	default:
		return CIStateUnknown
	}
}

func isGitLabNotFound(err error) bool {
	if err == nil {
		return false
	}
	// GitLab SDK returns 404 for not found resources
	return strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "Not Found")
}
