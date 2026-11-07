package apperr

import (
	"errors"
	"fmt"
	"testing"
)

func TestIsValidationError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"plain validation", Validation("duplicate IAM user"), true},
		{"formatted validation", Validationf("role %q not found", "dev"), true},
		{"wrapped cause", Validationf("load existing role: %w", errors.New("db down")), true},
		{"deeply wrapped", fmt.Errorf("resolve AUTO approvers: %w", Validation("no active approvers")), true},
		{"plain error", errors.New("database down"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsValidationError(tc.err); got != tc.want {
				t.Fatalf("IsValidationError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestValidationfSupportsWrapVerb(t *testing.T) {
	cause := errors.New("inventory lookup failed")
	err := Validationf("load existing role %q: %w", "dev", cause)
	if got := err.Error(); got != `load existing role "dev": inventory lookup failed` {
		t.Fatalf("Error() = %q", got)
	}
	if !errors.Is(err, cause) {
		t.Fatal("errors.Is should traverse the wrapped cause")
	}
}

func TestValidationPreservesMessage(t *testing.T) {
	err := Validation("该角色已有内嵌策略批量纳管工单在处理中，请稍后重试")
	if got := err.Error(); got != "该角色已有内嵌策略批量纳管工单在处理中，请稍后重试" {
		t.Fatalf("Error() = %q", got)
	}
}
