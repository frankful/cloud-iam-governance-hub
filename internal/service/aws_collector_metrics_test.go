package service

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func newAWSConfigWithHTTPClientForTest(client *http.Client) aws.Config {
	return aws.Config{HTTPClient: client}
}

// C1a：同步阶段指标机制的单测。collectIAMAssets 的子阶段计时与
// SyncConfiguredAccount 的 run 级阶段由既有 E2E/单测覆盖（fake IAM client
// 走同一代码路径），这里聚焦计数与归因的纯逻辑。

type stubRoundTripper struct {
	calls   int
	failErr error
}

func (stub *stubRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	stub.calls++
	if stub.failErr != nil {
		return nil, stub.failErr
	}
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}

func TestAWSRequestCounterCountsAndDelegates(t *testing.T) {
	counter := newAWSRequestCounter()
	stub := &stubRoundTripper{}
	counter.next = stub
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://iam.amazonaws.com", nil)
	for i := 0; i < 2; i++ {
		response, err := counter.RoundTrip(request)
		if err != nil {
			t.Fatalf("RoundTrip() error = %v", err)
		}
		response.Body.Close()
	}
	if counter.total() != 2 {
		t.Fatalf("counter.total() = %d, want 2", counter.total())
	}
	if stub.calls != 2 {
		t.Fatalf("stub.calls = %d, want 2 (counter must delegate)", stub.calls)
	}
}

func TestAWSRequestCounterAttachReusesExistingTransport(t *testing.T) {
	counter := newAWSRequestCounter()
	stub := &stubRoundTripper{}
	cfg := counter.attach(newAWSConfigWithHTTPClientForTest(&http.Client{Transport: stub}))
	// cfg 的 HTTPClient 必须是包着 counter 的 *http.Client，而 counter 的
	// next 换成了原有 stub。
	httpClient, ok := cfg.HTTPClient.(*http.Client)
	if !ok || httpClient.Transport != http.RoundTripper(counter) {
		t.Fatalf("attach() did not install counter as transport")
	}
}

func TestSyncRunMetricsStageRequestAttribution(t *testing.T) {
	counter := newAWSRequestCounter()
	metrics := newSyncRunMetrics(counter)

	metrics.record("ensure_account", 10)
	if got := metrics.stages[0].requests; got != 0 {
		t.Fatalf("stage 0 requests = %d, want 0 (no requests yet)", got)
	}

	counter.count.Store(5)
	metrics.record("collect", 100)
	if got := metrics.stages[1].requests; got != 5 {
		t.Fatalf("stage 1 requests = %d, want 5 (delta)", got)
	}

	counter.count.Store(8)
	metrics.record("persist", 20)
	if got := metrics.stages[2].requests; got != 3 {
		t.Fatalf("stage 2 requests = %d, want 3 (delta)", got)
	}
}

func TestSyncRunMetricsStageWrapsErrors(t *testing.T) {
	metrics := newSyncRunMetrics(newAWSRequestCounter())
	want := errors.New("boom")
	got := metrics.stage("collect", func() error { return want })
	if !errors.Is(got, want) {
		t.Fatalf("stage() error = %v, want %v", got, want)
	}
	if len(metrics.stages) != 1 || metrics.stages[0].name != "collect" {
		t.Fatalf("stages = %+v, want single 'collect' entry", metrics.stages)
	}
}

func TestTimedHelpersNilSafe(t *testing.T) {
	var metrics *syncRunMetrics
	value, err := timedResult(metrics, "collect.groups", func() (int, error) {
		return 42, nil
	})
	if err != nil || value != 42 {
		t.Fatalf("timedResult(nil) = %d, %v; want 42, nil", value, err)
	}
	if err := timedError(metrics, "collect.roles", func() error { return nil }); err != nil {
		t.Fatalf("timedError(nil) error = %v", err)
	}
	if fields := metrics.logFields(); len(fields) != 0 {
		t.Fatalf("nil metrics logFields() = %v, want empty", fields)
	}
}
