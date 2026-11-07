package service

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// 漂移发现的稳定标识（phase4-drift-design.md §2 / §3）。这些值会进数据库
// 的 CHECK 约束与前端过滤参数，改动必须配迁移。
const (
	DriftSourceInventory = "inventory"
	DriftSourceCI        = "ci"
	DriftSourcePublish   = "publish"

	DriftChangeAttribute       = "attribute"
	DriftChangeDeclaredMissing = "declared_missing"
	DriftChangeUndeclaredExtra = "undeclared_extra"
	DriftChangeFileConflict    = "file_conflict"
	DriftChangeBaselineStale   = "baseline_stale"

	DriftStatusSuspect           = "SUSPECT"
	DriftStatusOpen              = "OPEN"
	DriftStatusPending           = "PENDING"
	DriftStatusPendingRebaseline = "PENDING_REBASELINE"
	DriftStatusIgnored           = "IGNORED"

	DriftSeverityLow      = "LOW"
	DriftSeverityMedium   = "MEDIUM"
	DriftSeverityHigh     = "HIGH"
	DriftSeverityCritical = "CRITICAL"

	// 摘要的语义码（C16）。summary 由服务端拼中文，界面切到英文后无法就地
	// 翻译；和基线 issue 一样给出 code + params，前端按当前语言渲染，
	// summary 只作为兜底（webhook 等外部消费者仍读它）。
	DriftSummaryDeclaredMissing = "declared_missing"
	DriftSummaryUndeclaredExtra = "undeclared_extra"
	DriftSummaryBaselineStale   = "baseline_stale"
	DriftSummaryAttribute       = "attribute"
	DriftSummaryAttributeFields = "attribute_fields"
	DriftSummaryFileConflict    = "file_conflict"

	// 子资源标签码：前端 drift.child.<code>。
	DriftChildAttachment = "attachment"
	DriftChildMembership = "membership"
	DriftChildInline     = "inline_policy"
	DriftChildResource   = "resource"
)

// DriftFieldDiff 是一个字段的「声明 vs 实态」差异。页面直接渲染这张表，
// 不再回头查库存——判定当时的证据必须跟着发现一起存档。
type DriftFieldDiff struct {
	Field    string `json:"field"`
	Declared any    `json:"declared"`
	Live     any    `json:"live"`
}

// DriftFinding 是一条漂移发现。ResourceAddress 留空表示资源级发现（或
// 文件级，如 baseline_stale）；有值表示同一资源下的子地址（Terraform
// address），与资源 key 一起参与唯一索引。
type DriftFinding struct {
	ID              int64            `json:"id"`
	AccountDBID     int64            `json:"account_db_id"`
	AWSAccountID    string           `json:"aws_account_id"`
	Source          string           `json:"source"`
	ResourceKey     string           `json:"resource_key,omitempty"`
	ResourceAddress string           `json:"resource_address,omitempty"`
	Kind            string           `json:"kind,omitempty"`
	FileKey         string           `json:"file_key,omitempty"`
	ChangeType      string           `json:"change_type"`
	Fields          []DriftFieldDiff `json:"fields"`
	Severity        string           `json:"severity"`
	Status          string           `json:"status"`

	// BaselinePublicationID 是判定所用的基准发布，追责要能回答「拿哪一版
	// 声明比出来的」。
	BaselinePublicationID *int64 `json:"baseline_publication_id,omitempty"`

	Summary     string     `json:"summary,omitempty"`
	// SummaryCode/SummaryParams 让前端按界面语言渲染摘要；Summary 保留为
	// 兜底（历史行没有码，webhook 推送也需要一段可直接读的文本）。
	SummaryCode   string            `json:"summary_code,omitempty"`
	SummaryParams map[string]string `json:"summary_params,omitempty"`
	CIURL         string            `json:"ci_url,omitempty"`
	CommitSHA     string            `json:"commit_sha,omitempty"`
	FirstSeenAt   time.Time         `json:"first_seen_at"`
	LastSeenAt    time.Time         `json:"last_seen_at"`
	Occurrences   int               `json:"occurrences"`
	ResolvedAt    *time.Time        `json:"resolved_at,omitempty"`
	ResolvedBy    string            `json:"resolved_by,omitempty"`
}

// driftKey 是唯一索引里的身份：账号内同一来源同一资源（含子地址）只有
// 一条未解决发现。
func (finding DriftFinding) driftKey() string {
	return finding.ResourceKey + "\x00" + finding.ResourceAddress
}

// driftSeverity 判断一条差异的严重度。不追求精确评分，只要让「谁能改
// 信任关系 / 权限文档」浮到最上面：这两类被改等于权限边界被改。
func driftSeverity(changeType, kind string, fields []DriftFieldDiff) string {
	switch changeType {
	case DriftChangeDeclaredMissing:
		return DriftSeverityHigh
	case DriftChangeBaselineStale:
		return DriftSeverityMedium
	case DriftChangeUndeclaredExtra:
		return DriftSeverityMedium
	case DriftChangeFileConflict:
		return DriftSeverityMedium
	}
	severity := DriftSeverityLow
	for _, field := range fields {
		switch field.Field {
		case "trust_policy", "document", "permissions_boundary", "url", "client_ids":
			return DriftSeverityHigh
		case "members", "principal", "policy_arn", "role":
			if severity == DriftSeverityLow {
				severity = DriftSeverityMedium
			}
		}
	}
	// 策略文档被改（哪怕只是 Statement 增减）比标签变动严重得多；上面的
	// 循环已经把 document 归到 HIGH，这里只兜底未知 kind。
	if kind == BaselineKindPolicy || kind == BaselineKindInlinePolicy {
		if severity == DriftSeverityLow {
			severity = DriftSeverityMedium
		}
	}
	return severity
}

// applyDriftSummary 生成一句人话，页面列表与 webhook 共用。刻意写清楚「声明
// 是什么、实态是什么」，而不是只给一个 change_type。
//
// 同时给出语义码与参数（C16）：summary 是服务端中文，界面切英文后没法就地
// 翻译，所以前端优先按 summary_code + summary_params 渲染，summary 只作兜底。
func applyDriftSummary(finding *DriftFinding) {
	resource := driftResourceLabel(*finding)
	switch finding.ChangeType {
	case DriftChangeDeclaredMissing:
		finding.Summary = fmt.Sprintf("声明过的 %s 在线上已不存在", resource)
		finding.SummaryCode = DriftSummaryDeclaredMissing
		finding.SummaryParams = map[string]string{"resource": resource}
	case DriftChangeUndeclaredExtra:
		child := driftChildCode(finding.Kind)
		finding.Summary = fmt.Sprintf("%s 多出一条未声明的%s", resource, driftChildLabel(finding.Kind))
		finding.SummaryCode = DriftSummaryUndeclaredExtra
		finding.SummaryParams = map[string]string{"resource": resource, "child": child}
	case DriftChangeBaselineStale:
		file := finding.FileKey + ".tf"
		finding.Summary = fmt.Sprintf("基准过期：%s 在 main 上被改动过，差异不能判定为漂移，请重发基线", file)
		finding.SummaryCode = DriftSummaryBaselineStale
		finding.SummaryParams = map[string]string{"file": file}
	default:
		names := make([]string, 0, len(finding.Fields))
		for _, field := range finding.Fields {
			names = append(names, field.Field)
		}
		if len(names) == 0 {
			finding.Summary = fmt.Sprintf("%s 与声明不一致", resource)
			finding.SummaryCode = DriftSummaryAttribute
			finding.SummaryParams = map[string]string{"resource": resource}
			return
		}
		finding.Summary = fmt.Sprintf("%s 的 %s 与声明不一致", resource, strings.Join(names, ", "))
		finding.SummaryCode = DriftSummaryAttributeFields
		finding.SummaryParams = map[string]string{
			"resource": resource,
			"fields":   strings.Join(names, ", "),
		}
	}
}

func driftResourceLabel(finding DriftFinding) string {
	if finding.ResourceKey != "" {
		return finding.ResourceKey
	}
	return finding.Kind
}

// driftChildCode 返回子资源标签的语义码（前端 drift.child.<code>）。未知
// kind 归到「资源」，与旧的兜底文案一致。
func driftChildCode(kind string) string {
	switch kind {
	case DriftChildAttachment:
		return DriftChildAttachment
	case DriftChildMembership:
		return DriftChildMembership
	case BaselineKindInlinePolicy:
		return DriftChildInline
	default:
		return DriftChildResource
	}
}

func driftChildLabel(kind string) string {
	switch kind {
	case DriftChildAttachment:
		return "策略挂载"
	case DriftChildMembership:
		return "组成员"
	case BaselineKindInlinePolicy:
		return "内联策略"
	default:
		return "资源"
	}
}

// compareDeclaredAttributes 只比对「声明里写了的字段」。生成器没写的字段
// 表示 Terraform 不管它，拿实态的默认值去比会制造结构性误报（例如
// 基线不声明 tags 时，实态任何标签都会被报成漂移）。
func compareDeclaredAttributes(declared map[string]any, live map[string]any) []DriftFieldDiff {
	diffs := make([]DriftFieldDiff, 0, 4)
	fields := make([]string, 0, len(declared))
	for field := range declared {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	for _, field := range fields {
		declaredValue := declared[field]
		liveValue, present := live[field]
		if !present {
			diffs = append(diffs, DriftFieldDiff{
				Field: field, Declared: declaredValue, Live: nil,
			})
			continue
		}
		normalizedDeclared, err := normalizeDriftValue(field, declaredValue)
		if err != nil {
			continue
		}
		normalizedLive, err := normalizeDriftValue(field, liveValue)
		if err != nil {
			continue
		}
		if driftValuesEqual(normalizedDeclared, normalizedLive) {
			continue
		}
		diffs = append(diffs, DriftFieldDiff{
			Field: field, Declared: declaredValue, Live: liveValue,
		})
	}
	return diffs
}

// normalizeDriftValue 把「同一个语义的不同写法」折叠成一个可比较的值。
// 这一层只处理确定性等价：path 的斜杠、字符串集合的顺序、策略文档的
// 键序与数组顺序。语义不等价的东西一律不折叠——宁可误报，不可漏报。
func normalizeDriftValue(field string, value any) (any, error) {
	switch field {
	case "path":
		return normalizeIAMPath(fmt.Sprintf("%v", value)), nil
	case "tags":
		return normalizeStringMap(value)
	case "members", "client_ids", "thumbprints":
		return normalizeStringSet(value)
	case "trust_policy", "document":
		return normalizePolicyDocument(value)
	default:
		return normalizeScalar(value)
	}
}

// normalizeIAMPath 把 "" 与 "/" 视为同一路径，其余只补足首尾斜杠：
// IAM 的 path 默认值是 "/"，但采集与生成两条链路的写法不一致。
func normalizeIAMPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "/"
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	if !strings.HasSuffix(trimmed, "/") {
		trimmed += "/"
	}
	return trimmed
}

func normalizeStringMap(value any) (map[string]string, error) {
	switch typed := value.(type) {
	case nil:
		return map[string]string{}, nil
	case map[string]string:
		return typed, nil
	case map[string]any:
		normalized := make(map[string]string, len(typed))
		for key, item := range typed {
			normalized[key] = fmt.Sprintf("%v", item)
		}
		return normalized, nil
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return nil, err
		}
		var decoded map[string]any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			return nil, err
		}
		normalized := make(map[string]string, len(decoded))
		for key, item := range decoded {
			normalized[key] = fmt.Sprintf("%v", item)
		}
		return normalized, nil
	}
}

func normalizeStringSet(value any) ([]string, error) {
	switch typed := value.(type) {
	case nil:
		return []string{}, nil
	case []string:
		sorted := append([]string(nil), typed...)
		sort.Strings(sorted)
		return sorted, nil
	case []any:
		sorted := make([]string, 0, len(typed))
		for _, item := range typed {
			sorted = append(sorted, fmt.Sprintf("%v", item))
		}
		sort.Strings(sorted)
		return sorted, nil
	default:
		return []string{fmt.Sprintf("%v", typed)}, nil
	}
}

// normalizePolicyDocument 把策略文档折叠成「键序无关、数组集合无关」的
// 结构。IAM 策略里 Statement/Action/Resource 的顺序没有语义，声明侧与
// 采集侧只要序列化顺序不同就会被报成漂移——那是纯噪音。
func normalizePolicyDocument(value any) (any, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case string:
		var decoded any
		if err := json.Unmarshal([]byte(typed), &decoded); err != nil {
			// 不是合法 JSON：保留原文，让差异可见而不是静默吞掉。
			return typed, nil
		}
		return normalizePolicyDocument(decoded)
	case json.RawMessage:
		// RawMessage 是 []byte 的具名类型，类型 switch 不会落到 []byte 分支：
		// 漏掉这一条会让所有声明里的策略文档永远「不相等」。
		return normalizePolicyDocument(string(typed))
	case []byte:
		return normalizePolicyDocument(string(typed))
	case map[string]any:
		normalized := make(map[string]any, len(typed))
		for key, item := range typed {
			item, err := normalizePolicyDocument(item)
			if err != nil {
				return nil, err
			}
			normalized[key] = item
		}
		return normalized, nil
	case []any:
		allStrings := len(typed) > 0
		for _, item := range typed {
			if _, ok := item.(string); !ok {
				allStrings = false
				break
			}
		}
		if allStrings {
			values := make([]string, 0, len(typed))
			for _, item := range typed {
				values = append(values, item.(string))
			}
			sort.Strings(values)
			return values, nil
		}
		normalized := make([]any, 0, len(typed))
		for _, item := range typed {
			item, err := normalizePolicyDocument(item)
			if err != nil {
				return nil, err
			}
			normalized = append(normalized, item)
		}
		return normalized, nil
	default:
		return normalizeScalar(value)
	}
}

// normalizeScalar 把 JSON 解码出来的数字统一成 float64：声明侧来自
// SQL 扫描（int64），库存侧来自 JSONB（float64），直接比较会永远不等。
func normalizeScalar(value any) (any, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case json.Number:
		parsed, err := typed.Float64()
		if err != nil {
			return typed.String(), nil
		}
		return parsed, nil
	case int:
		return float64(typed), nil
	case int32:
		return float64(typed), nil
	case int64:
		return float64(typed), nil
	case float32:
		return float64(typed), nil
	case float64:
		return typed, nil
	default:
		return value, nil
	}
}

func driftValuesEqual(left, right any) bool {
	leftJSON, err := json.Marshal(left)
	if err != nil {
		return false
	}
	rightJSON, err := json.Marshal(right)
	if err != nil {
		return false
	}
	return string(leftJSON) == string(rightJSON)
}
