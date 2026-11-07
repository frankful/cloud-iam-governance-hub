package githost

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGitLabHostMergesThroughProviderAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut ||
			!strings.HasSuffix(request.URL.Path, "/projects/17/merge_requests/42/merge") {
			t.Errorf("request = %s %s, want PUT merge-request merge endpoint", request.Method, request.URL.Path)
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"iid":42,"state":"merged"}`))
	}))
	defer server.Close()

	host, err := NewGitLabHost(GitHostConfig{
		Provider: "gitlab", BaseURL: server.URL + "/api/v4", Token: "token", ProjectID: "17",
	})
	if err != nil {
		t.Fatalf("NewGitLabHost() error = %v", err)
	}
	if err := host.MergeMergeRequest(context.Background(), "17", "42"); err != nil {
		t.Fatalf("MergeMergeRequest() error = %v", err)
	}
}
