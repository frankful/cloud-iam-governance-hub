package service

import (
	"context"
	"testing"
)

// 回归：key 曾被整体转小写，而 AWS 资源名大小写敏感——小写名在 UPDATE 里
// 静默匹配零行，接口返回「资源不存在」。kind 前缀不区分大小写，名字必须保原样。
func TestParseOwnershipKeyKeepsNameCase(t *testing.T) {
	kind, name, err := ParseOwnershipKey("POLICY-Cloudtrail-CW-Access")
	if err != nil {
		t.Fatalf("ParseOwnershipKey error = %v", err)
	}
	if kind != "policy" {
		t.Errorf("kind = %q, want policy", kind)
	}
	if name != "Cloudtrail-CW-Access" {
		t.Errorf("name = %q, want 原始大小写 Cloudtrail-CW-Access", name)
	}

	if _, _, err := ParseOwnershipKey("no-dash"); err == nil {
		t.Error("无 kind 前缀的 key 应报错")
	}
	if _, _, err := ParseOwnershipKey("policy-"); err == nil {
		t.Error("空名字的 key 应报错")
	}
	if _, _, err := ParseOwnershipKey("bucket-thing"); err == nil {
		t.Error("未知 kind 应报错")
	}
}

type fakeOwnershipRepository struct {
	setCalls []string
	setErr   error
	list     []ResourceOwnership
}

func (repository *fakeOwnershipRepository) SetOwnership(
	_ context.Context, _ int64, kind, name, managedBy, reviewedBy string,
) error {
	if repository.setErr != nil {
		return repository.setErr
	}
	repository.setCalls = append(repository.setCalls, kind+"|"+name+"|"+managedBy+"|"+reviewedBy)
	return nil
}

func (repository *fakeOwnershipRepository) ListOwnership(
	_ context.Context, _ int64, _, _ string,
) ([]ResourceOwnership, error) {
	return repository.list, nil
}

// reviewer 必须原样透传到仓库层：归属标注决定基线能碰什么，审计要能追到人。
func TestSetOwnershipPassesReviewer(t *testing.T) {
	repository := &fakeOwnershipRepository{}
	service, err := NewIAMOwnershipService(repository)
	if err != nil {
		t.Fatalf("NewIAMOwnershipService error = %v", err)
	}
	if err := service.SetOwnership(context.Background(), 1, "role-Otel-Collector", "external", "  admin  "); err != nil {
		t.Fatalf("SetOwnership error = %v", err)
	}
	if len(repository.setCalls) != 1 {
		t.Fatalf("setCalls = %v, want 1", repository.setCalls)
	}
	if repository.setCalls[0] != "role|Otel-Collector|external|admin" {
		t.Errorf("call = %q, want role|Otel-Collector|external|admin", repository.setCalls[0])
	}

	if err := service.SetOwnership(context.Background(), 1, "role-x", "nobody", "admin"); err == nil {
		t.Error("非法 managed_by 应报错")
	}
	if err := service.SetOwnership(context.Background(), 0, "role-x", "external", "admin"); err == nil {
		t.Error("account_id 必须为正")
	}
}
