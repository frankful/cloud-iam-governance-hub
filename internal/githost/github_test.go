package githost

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewGitHubHostDefaultsBaseURL(t *testing.T) {
	host, err := NewGitHubHost(GitHostConfig{
		Provider:  "github",
		Token:     "token",
		ProjectID: "owner/repo",
	})
	if err != nil {
		t.Fatalf("NewGitHubHost() error = %v", err)
	}
	// An empty BaseURL must fall back to the public GitHub API; otherwise
	// FetchMergeRequest issues schemeless requests ("unsupported protocol
	// scheme \"\"") and every gitstatus poll fails.
	if host.config.BaseURL != "https://api.github.com" {
		t.Fatalf("BaseURL = %q, want %q", host.config.BaseURL, "https://api.github.com")
	}
}

func TestNewGitHubHostTrimsBaseURLTrailingSlash(t *testing.T) {
	host, err := NewGitHubHost(GitHostConfig{
		Provider:  "github",
		BaseURL:   "https://github.example.com/api/v3/",
		Token:     "token",
		ProjectID: "owner/repo",
	})
	if err != nil {
		t.Fatalf("NewGitHubHost() error = %v", err)
	}
	if host.config.BaseURL != "https://github.example.com/api/v3" {
		t.Fatalf("BaseURL = %q, want trailing slash trimmed", host.config.BaseURL)
	}
}

func TestNewGitHubHostRequiresTokenAndProject(t *testing.T) {
	if _, err := NewGitHubHost(GitHostConfig{Provider: "github", ProjectID: "owner/repo"}); err == nil {
		t.Fatal("NewGitHubHost() without token: error = nil, want error")
	}

	if _, err := NewGitHubHost(GitHostConfig{Provider: "github", Token: "token"}); err == nil {
		t.Fatal("NewGitHubHost() without project: error = nil, want error")
	}
}

func TestGitHubHostMergesThroughProviderAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut || request.URL.Path != "/repos/owner/repo/pulls/42/merge" {
			t.Errorf("request = %s %s, want PUT pull-request merge endpoint", request.Method, request.URL.Path)
			http.NotFound(writer, request)
			return
		}
		var body map[string]string
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode merge request body: %v", err)
		}
		if body["merge_method"] != "merge" {
			t.Errorf("merge_method = %q, want merge", body["merge_method"])
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(writer, `{"merged":true,"message":"Pull Request successfully merged"}`)
	}))
	defer server.Close()

	host, err := NewGitHubHost(GitHostConfig{
		Provider: "github", BaseURL: server.URL, Token: "token", ProjectID: "owner/repo",
	})
	if err != nil {
		t.Fatalf("NewGitHubHost() error = %v", err)
	}
	if err := host.MergeMergeRequest(context.Background(), "owner/repo", "42"); err != nil {
		t.Fatalf("MergeMergeRequest() error = %v", err)
	}
}
