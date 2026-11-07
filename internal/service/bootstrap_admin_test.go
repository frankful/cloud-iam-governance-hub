package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeBootstrapAdminStore struct {
	admins    int
	ensureErr error
	ensured   [][2]string // (userID, displayName) per EnsureAdminUser call
}

func (store *fakeBootstrapAdminStore) CountActiveAdmins(context.Context) (int, error) {
	return store.admins, nil
}

func (store *fakeBootstrapAdminStore) EnsureAdminUser(
	_ context.Context, userID, displayName string,
) error {
	if store.ensureErr != nil {
		return store.ensureErr
	}
	store.ensured = append(store.ensured, [2]string{userID, displayName})
	return nil
}

func newBootstrapTestService(t *testing.T) (*PlatformTokenService, *fakePlatformTokenRepository) {
	t.Helper()
	repository := &fakePlatformTokenRepository{
		// 自举刚把 admin 建好、授好角色，签发守卫必须放行。
		userExists: true,
		userRoles:  []string{"platform_admin"},
	}
	tokenService, err := NewPlatformTokenService(repository)
	if err != nil {
		t.Fatalf("NewPlatformTokenService() error = %v", err)
	}
	return tokenService, repository
}

// TestBootstrapAdminFirstStart：没有任何可用管理员时，创建 admin、签发 token
// 并把明文写进文件——这是全新安装第一次登录的唯一入口。
func TestBootstrapAdminFirstStart(t *testing.T) {
	tokenService, repository := newBootstrapTestService(t)
	store := &fakeBootstrapAdminStore{}
	tokenFile := filepath.Join(t.TempDir(), "bootstrap-admin-token.txt")

	result, err := BootstrapAdmin(context.Background(), store, tokenService, BootstrapAdminOptions{
		TTL:       24 * time.Hour,
		TokenFile: tokenFile,
	})
	if err != nil {
		t.Fatalf("BootstrapAdmin() error = %v", err)
	}
	if result.Skipped {
		t.Fatalf("result.Skipped = true, want first-start bootstrap: %+v", result)
	}
	if result.UserID != "admin" {
		t.Errorf("UserID = %q, want default admin", result.UserID)
	}
	if len(store.ensured) != 1 || store.ensured[0][0] != "admin" {
		t.Fatalf("EnsureAdminUser calls = %v, want one call for admin", store.ensured)
	}
	if repository.createCalls != 1 {
		t.Fatalf("CreateToken calls = %d, want 1", repository.createCalls)
	}
	if repository.actorID != "system" {
		t.Errorf("CreateToken actorID = %q, want system", repository.actorID)
	}
	if repository.expiresAt == nil || !repository.expiresAt.After(time.Now()) {
		t.Errorf("CreateToken expiresAt = %v, want a future timestamp", repository.expiresAt)
	}

	content, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	if !strings.Contains(string(content), result.Token.Token) {
		t.Errorf("token file does not contain the plaintext token:\n%s", content)
	}
	if !strings.Contains(string(content), "admin") {
		t.Errorf("token file does not name the user:\n%s", content)
	}
	if result.TokenFile != tokenFile {
		t.Errorf("result.TokenFile = %q, want %q", result.TokenFile, tokenFile)
	}
}

// TestBootstrapAdminSkipsWhenAdminExists：已有可用管理员时不得铸造新凭证——
// 重启/重新部署绝不能悄悄多出一枚有效 token。
func TestBootstrapAdminSkipsWhenAdminExists(t *testing.T) {
	tokenService, repository := newBootstrapTestService(t)
	store := &fakeBootstrapAdminStore{admins: 2}
	tokenFile := filepath.Join(t.TempDir(), "bootstrap-admin-token.txt")

	result, err := BootstrapAdmin(context.Background(), store, tokenService, BootstrapAdminOptions{
		TokenFile: tokenFile,
	})
	if err != nil {
		t.Fatalf("BootstrapAdmin() error = %v", err)
	}
	if !result.Skipped {
		t.Fatalf("result.Skipped = false, want skip: %+v", result)
	}
	if result.Token != nil {
		t.Errorf("result.Token = %+v, want nil on skip", result.Token)
	}
	if len(store.ensured) != 0 {
		t.Errorf("EnsureAdminUser calls = %v, want none on skip", store.ensured)
	}
	if repository.createCalls != 0 {
		t.Errorf("CreateToken calls = %d, want 0 on skip", repository.createCalls)
	}
	if _, err := os.Stat(tokenFile); !os.IsNotExist(err) {
		t.Errorf("token file must not be written on skip, stat error = %v", err)
	}
}

// TestBootstrapAdminWithoutFile：TokenFile 置空则不落盘，secret 只存在于
// 返回值里（调用方自行决定去向，例如打进 stdout）。
func TestBootstrapAdminWithoutFile(t *testing.T) {
	tokenService, _ := newBootstrapTestService(t)
	store := &fakeBootstrapAdminStore{}

	result, err := BootstrapAdmin(context.Background(), store, tokenService, BootstrapAdminOptions{})
	if err != nil {
		t.Fatalf("BootstrapAdmin() error = %v", err)
	}
	if result.Skipped || result.Token == nil {
		t.Fatalf("result = %+v, want a fresh token", result)
	}
	if result.TokenFile != "" {
		t.Errorf("result.TokenFile = %q, want empty when disabled", result.TokenFile)
	}
}
