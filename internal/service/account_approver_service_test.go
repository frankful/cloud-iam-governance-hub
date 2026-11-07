package service

import (
	"reflect"
	"testing"
)

// TestNormalizeApproverAccountIDs 用户管理页提交的账号集合来自多选框，顺序
// 随机、允许重复；规范化后必须稳定（排序 + 去重），否则每次保存都会产生
// 无意义的 DELETE/INSERT 抖动。
func TestNormalizeApproverAccountIDs(t *testing.T) {
	cases := []struct {
		name  string
		input []int64
		want  []int64
	}{
		{"nil becomes empty slice", nil, []int64{}},
		{"sorts ascending", []int64{9, 3, 7}, []int64{3, 7, 9}},
		{"dedupes", []int64{7, 7, 3}, []int64{3, 7}},
		{"drops non-positive ids", []int64{0, -2, 5}, []int64{5}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := normalizeApproverAccountIDs(testCase.input)
			if !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("normalizeApproverAccountIDs(%v) = %v, want %v",
					testCase.input, got, testCase.want)
			}
		})
	}
}
