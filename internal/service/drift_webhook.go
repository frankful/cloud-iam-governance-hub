package service

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// 通用 webhook 出口（phase4-drift-design.md §8）。
//
// 只做一件事：有新的漂移发现时，往 `DRIFT_WEBHOOK_URL` POST 一条 JSON。不接
// 邮件/Slack 适配器——那属于使用方的一次性脚本，平台提供一个稳定的 JSON
// 契约就够了。
//
// 三条硬约束：
//   1. 异步：判定挂在同步结束点，同步不能因为告警端点慢而变慢；
//   2. 失败只记日志、不重试：告警丢了比把同步拖垮划算，发现本身在库里；
//   3. 负载有上限：一次判定可能冒出上百条，截断并带上总数，避免把接收方打爆。

const (
	// driftWebhookTimeout 是单次投递的上限。超过就当对端不可用。
	driftWebhookTimeout = 10 * time.Second
	// driftWebhookMaxFindings 限制单条消息里的发现数。
	driftWebhookMaxFindings = 50
)

// DriftNotifier 把发现变成一次 HTTP POST。URL 为空时构造出 nil，调用方无需
// 判断是否「配置了 webhook」。
type DriftNotifier struct {
	url    string
	client *http.Client
	logger *slog.Logger
}

func NewDriftNotifier(url string, logger *slog.Logger) *DriftNotifier {
	url = strings.TrimSpace(url)
	if url == "" {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DriftNotifier{
		url:    url,
		client: &http.Client{Timeout: driftWebhookTimeout},
		logger: logger,
	}
}

// driftWebhookPayload 是对外契约。字段名故意与 API 的 JSON 保持一致，使用方
// 拿到 payload 就能直接对上页面看到的同一条发现。
type driftWebhookPayload struct {
	Event      string         `json:"event"`
	OccurredAt time.Time      `json:"occurred_at"`
	Total      int            `json:"total"`
	Truncated  bool           `json:"truncated"`
	Findings   []DriftFinding `json:"findings"`
}

// Notify 异步投递。调用方不等待结果，也不应依赖它成功。
func (notifier *DriftNotifier) Notify(event string, findings []DriftFinding) {
	if notifier == nil || len(findings) == 0 {
		return
	}
	payload := driftWebhookPayload{
		Event:      event,
		OccurredAt: time.Now().UTC(),
		Total:      len(findings),
	}
	if len(findings) > driftWebhookMaxFindings {
		payload.Findings = findings[:driftWebhookMaxFindings]
		payload.Truncated = true
	} else {
		payload.Findings = findings
	}
	body, err := json.Marshal(payload)
	if err != nil {
		notifier.logger.Warn("failed to encode drift webhook payload", "event", event, "error", err)
		return
	}
	go notifier.deliver(event, body)
}

func (notifier *DriftNotifier) deliver(event string, body []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), driftWebhookTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, notifier.url, bytes.NewReader(body))
	if err != nil {
		notifier.logger.Warn("failed to build drift webhook request", "event", event, "error", err)
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "iam-governance-hub-drift-webhook")
	response, err := notifier.client.Do(request)
	if err != nil {
		notifier.logger.Warn("drift webhook delivery failed", "event", event, "error", err)
		return
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusMultipleChoices {
		notifier.logger.Warn("drift webhook rejected",
			"event", event, "status", response.StatusCode)
		return
	}
	notifier.logger.Info("drift webhook delivered", "event", event, "status", response.StatusCode)
}
