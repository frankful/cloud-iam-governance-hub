package githost

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// defaultGitHubAPIURL is the public GitHub API endpoint used when a
// caller does not configure BaseURL (e.g. GITHUB_API_URL is unset).
const defaultGitHubAPIURL = "https://api.github.com"

// GitHubHost implements GitHost for GitHub.
type GitHubHost struct {
	config GitHostConfig
	client *http.Client
}

// NewGitHubHost creates a new GitHub GitHost client.
func NewGitHubHost(config GitHostConfig) (*GitHubHost, error) {
	if config.Token == "" {
		return nil, fmt.Errorf("GitHub token must not be empty")
	}
	if config.ProjectID == "" {
		return nil, fmt.Errorf("GitHub repository (owner/repo) must not be empty")
	}
	// Default BaseURL the same way the ticket publisher does: without a
	// fallback an empty BaseURL produces schemeless requests such as
	// Get "/repos/owner/repo/pulls/1" (unsupported protocol scheme ""),
	// which failed every gitstatus poll when the embedded worker ran
	// with GITHUB_API_URL unset.
	if baseURL := strings.TrimRight(strings.TrimSpace(config.BaseURL), "/"); baseURL != "" {
		config.BaseURL = baseURL
	} else {
		config.BaseURL = defaultGitHubAPIURL
	}

	return &GitHubHost{
		config: config,
		client: &http.Client{
			Timeout: 30 * time.Second,
			// otelhttp creates one span per GitHub API call; no-op without a provider.
			Transport: otelhttp.NewTransport(http.DefaultTransport),
		},
	}, nil
}

// FetchMergeRequest retrieves the current status of a GitHub pull request.
func (h *GitHubHost) FetchMergeRequest(ctx context.Context, project string, number string) (*MergeRequestStatus, error) {
	url := fmt.Sprintf("%s/repos/%s/pulls/%s", h.config.BaseURL, project, number)

	var pr struct {
		Number         int        `json:"number"`
		HTMLURL        string     `json:"html_url"`
		State          string     `json:"state"`
		Title          string     `json:"title"`
		MergedAt       *time.Time `json:"merged_at"`
		MergeCommitSHA string     `json:"merge_commit_sha"`
		Head           struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	}

	if err := h.request(ctx, http.MethodGet, url, nil, &pr); err != nil {
		if isGitHubNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("fetch GitHub pull request: %w", err)
	}

	state := MergeStateUnknown
	if pr.State == "open" {
		state = MergeStateOpen
	} else if pr.State == "closed" {
		if pr.MergedAt != nil {
			state = MergeStateMerged
		} else {
			state = MergeStateClosed
		}
	}

	return &MergeRequestStatus{
		Number:       number,
		URL:          pr.HTMLURL,
		State:        state,
		MergeCommit:  pr.MergeCommitSHA,
		HeadSHA:      pr.Head.SHA,
		BaseBranch:   pr.Base.Ref,
		SourceBranch: pr.Head.Ref,
		Title:        pr.Title,
		UpdatedAt:    time.Now(),
	}, nil
}

// FetchPipelineStatus retrieves the current status of a GitHub Actions workflow run.
func (h *GitHubHost) FetchPipelineStatus(ctx context.Context, project string, pipelineID string) (*PipelineStatus, error) {
	url := fmt.Sprintf("%s/repos/%s/actions/runs/%s", h.config.BaseURL, project, pipelineID)

	var run struct {
		ID         int64      `json:"id"`
		Name       string     `json:"name"`
		Status     string     `json:"status"`
		Conclusion string     `json:"conclusion"`
		HeadSHA    string     `json:"head_sha"`
		CreatedAt  *time.Time `json:"created_at"`
		UpdatedAt  *time.Time `json:"updated_at"`
		HTMLURL    string     `json:"html_url"`
	}

	if err := h.request(ctx, http.MethodGet, url, nil, &run); err != nil {
		if isGitHubNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("fetch GitHub workflow run: %w", err)
	}

	return &PipelineStatus{
		ID:         pipelineID,
		Name:       run.Name,
		State:      mapGitHubCIState(run.Status, run.Conclusion),
		CommitSHA:  run.HeadSHA,
		StartedAt:  run.CreatedAt,
		FinishedAt: run.UpdatedAt,
		WebURL:     run.HTMLURL,
	}, nil
}

// FetchCommitStatuses retrieves the status of all GitHub check runs for a commit.
func (h *GitHubHost) FetchCommitStatuses(ctx context.Context, project string, commitSHA string) ([]PipelineStatus, error) {
	url := fmt.Sprintf("%s/repos/%s/commits/%s/check-runs", h.config.BaseURL, project, commitSHA)

	var response struct {
		TotalCount int `json:"total_count"`
		CheckRuns  []struct {
			ID          int64      `json:"id"`
			Name        string     `json:"name"`
			Status      string     `json:"status"`
			Conclusion  string     `json:"conclusion"`
			StartedAt   *time.Time `json:"started_at"`
			CompletedAt *time.Time `json:"completed_at"`
			HTMLURL     string     `json:"html_url"`
		} `json:"check_runs"`
	}

	if err := h.request(ctx, http.MethodGet, url, nil, &response); err != nil {
		return nil, fmt.Errorf("fetch GitHub check runs: %w", err)
	}

	statuses := make([]PipelineStatus, 0, len(response.CheckRuns))
	for _, run := range response.CheckRuns {
		statuses = append(statuses, PipelineStatus{
			ID:         fmt.Sprintf("%d", run.ID),
			Name:       run.Name,
			State:      mapGitHubCIState(run.Status, run.Conclusion),
			CommitSHA:  commitSHA,
			StartedAt:  run.StartedAt,
			FinishedAt: run.CompletedAt,
			WebURL:     run.HTMLURL,
		})
	}
	return statuses, nil
}

func (h *GitHubHost) MergeMergeRequest(ctx context.Context, project, number string) error {
	body := strings.NewReader(`{"merge_method":"merge"}`)
	var result struct {
		Merged  bool   `json:"merged"`
		Message string `json:"message"`
	}
	url := fmt.Sprintf("%s/repos/%s/pulls/%s/merge", h.config.BaseURL, project, number)
	if err := h.request(ctx, http.MethodPut, url, body, &result); err != nil {
		return fmt.Errorf("merge GitHub pull request: %w", err)
	}
	if !result.Merged {
		return fmt.Errorf("GitHub did not merge pull request %s: %s", number, result.Message)
	}
	return nil
}

func (h *GitHubHost) request(ctx context.Context, method, url string, body io.Reader, result interface{}) error {
	// GET 幂等：传输层瞬态错误（EOF/连接重置）短退避重试两次。PR 状态轮询
	// 与基线合并感知都靠这些读接口收敛，GitHub 网络抖动不应让一轮对账空转。
	maxAttempts := 1
	if method == http.MethodGet && body == nil {
		maxAttempts = 3
	}
	var resp *http.Response
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, reqErr := http.NewRequestWithContext(ctx, method, url, body)
		if reqErr != nil {
			return fmt.Errorf("create request: %w", reqErr)
		}
		req.Header.Set("Authorization", "Bearer "+h.config.Token)
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err = h.client.Do(req)
		if err == nil {
			break
		}
		if attempt == maxAttempts {
			return fmt.Errorf("execute request: %w", err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("execute request: %w", ctx.Err())
		case <-time.After(time.Duration(attempt) * 400 * time.Millisecond):
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &notFoundError{}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub API error: %d %s", resp.StatusCode, string(bodyBytes))
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}

	return nil
}

func mapGitHubCIState(status, conclusion string) CIState {
	switch status {
	case "queued", "waiting", "pending":
		return CIStatePending
	case "in_progress":
		return CIStateRunning
	case "completed":
		switch conclusion {
		case "success":
			return CIStateSucceeded
		case "failure":
			return CIStateFailed
		case "cancelled":
			return CIStateCanceled
		default:
			return CIStateUnknown
		}
	default:
		return CIStateUnknown
	}
}

func isGitHubNotFound(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*notFoundError)
	return ok
}

type notFoundError struct{}

func (e *notFoundError) Error() string {
	return "not found"
}
