package service

import "testing"

// 漂移摘要的语义码（台账 C16）。summary 是服务端拼的中文，界面切英文后
// 无法就地翻译；这里锁定「每一种变更类型都给出码 + 渲染所需的参数」，
// 少了任何一个，前端那一列就会退回中文兜底。
func TestApplyDriftSummaryCarriesCodes(t *testing.T) {
	cases := []struct {
		name        string
		finding     DriftFinding
		wantCode    string
		wantParams  []string
		wantSummary string
	}{
		{
			name: "declared missing",
			finding: DriftFinding{
				ChangeType:  DriftChangeDeclaredMissing,
				ResourceKey: "role:app",
				Kind:        "role",
			},
			wantCode:    DriftSummaryDeclaredMissing,
			wantParams:  []string{"resource"},
			wantSummary: "声明过的 role:app 在线上已不存在",
		},
		{
			name: "undeclared child",
			finding: DriftFinding{
				ChangeType:  DriftChangeUndeclaredExtra,
				ResourceKey: "role:app",
				Kind:        DriftChildAttachment,
			},
			wantCode:    DriftSummaryUndeclaredExtra,
			wantParams:  []string{"resource", "child"},
			wantSummary: "role:app 多出一条未声明的策略挂载",
		},
		{
			name: "stale baseline",
			finding: DriftFinding{
				ChangeType: DriftChangeBaselineStale,
				FileKey:    "role-app",
			},
			wantCode:    DriftSummaryBaselineStale,
			wantParams:  []string{"file"},
			wantSummary: "基准过期：role-app.tf 在 main 上被改动过，差异不能判定为漂移，请重发基线",
		},
		{
			name: "attribute without fields",
			finding: DriftFinding{
				ChangeType:  DriftChangeAttribute,
				ResourceKey: "user:alice",
			},
			wantCode:    DriftSummaryAttribute,
			wantParams:  []string{"resource"},
			wantSummary: "user:alice 与声明不一致",
		},
		{
			name: "attribute with fields",
			finding: DriftFinding{
				ChangeType:  DriftChangeAttribute,
				ResourceKey: "user:alice",
				Fields: []DriftFieldDiff{
					{Field: "path"},
					{Field: "tags"},
				},
			},
			wantCode:    DriftSummaryAttributeFields,
			wantParams:  []string{"resource", "fields"},
			wantSummary: "user:alice 的 path, tags 与声明不一致",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			finding := testCase.finding
			applyDriftSummary(&finding)
			if finding.SummaryCode != testCase.wantCode {
				t.Fatalf("summary_code = %q, want %q", finding.SummaryCode, testCase.wantCode)
			}
			if finding.Summary != testCase.wantSummary {
				t.Fatalf("summary = %q, want %q", finding.Summary, testCase.wantSummary)
			}
			for _, key := range testCase.wantParams {
				if finding.SummaryParams[key] == "" {
					t.Fatalf("summary_params[%q] is empty, want it filled: %v", key, finding.SummaryParams)
				}
			}
		})
	}
}

// 子资源标签也必须给码：前端要按语言渲染「策略挂载 / 组成员 / 内联策略」，
// 直接把中文塞进参数等于换个地方写死中文。
func TestDriftChildCodeMapsEveryKind(t *testing.T) {
	cases := map[string]string{
		DriftChildAttachment:     DriftChildAttachment,
		DriftChildMembership:     DriftChildMembership,
		BaselineKindInlinePolicy: DriftChildInline,
		"role":                   DriftChildResource,
		"":                       DriftChildResource,
	}
	for kind, want := range cases {
		if got := driftChildCode(kind); got != want {
			t.Errorf("driftChildCode(%q) = %q, want %q", kind, got, want)
		}
	}
}
