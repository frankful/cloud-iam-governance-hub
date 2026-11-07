package service

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakePlatformTokenRepository struct {
	userID      string
	actorID     string
	name        string
	prefix      string
	hash        []byte
	expiresAt   *time.Time
	identity    AuthenticatedIdentity
	createErr   error
	authErr     error
	createCalls int
	authCalls   int
	revokeCalls int
	revokeID    int64
	revokeActor string
	revokeAdmin bool
	tokens      []PlatformTokenInfo
	userExists  bool
	userRoles   []string
}

func (repository *fakePlatformTokenRepository) UserAuthz(
	_ context.Context,
	userID string,
) (bool, []string, error) {
	if repository.userID != "" && userID != repository.userID {
		return false, nil, nil
	}
	return repository.userExists, append([]string(nil), repository.userRoles...), nil
}

func (repository *fakePlatformTokenRepository) CreateToken(
	_ context.Context,
	actorID, userID, name, prefix string,
	hash []byte,
	expiresAt *time.Time,
) (int64, error) {
	repository.createCalls++
	repository.actorID = actorID
	repository.userID = userID
	repository.name = name
	repository.prefix = prefix
	repository.hash = append([]byte(nil), hash...)
	repository.expiresAt = expiresAt
	if repository.createErr != nil {
		return 0, repository.createErr
	}
	return 17, nil
}

func (repository *fakePlatformTokenRepository) ListTokens(
	_ context.Context,
	userID string,
) ([]PlatformTokenInfo, error) {
	if userID == "" {
		return repository.tokens, nil
	}
	filtered := make([]PlatformTokenInfo, 0)
	for _, token := range repository.tokens {
		if token.UserID == userID {
			filtered = append(filtered, token)
		}
	}
	return filtered, nil
}

func (repository *fakePlatformTokenRepository) AuthenticateToken(
	_ context.Context,
	hash []byte,
) (AuthenticatedIdentity, error) {
	repository.authCalls++
	if repository.authErr != nil {
		return AuthenticatedIdentity{}, repository.authErr
	}
	if !equalBytes(hash, repository.hash) {
		return AuthenticatedIdentity{}, ErrInvalidPlatformToken
	}
	return repository.identity, nil
}

func (repository *fakePlatformTokenRepository) RevokeToken(
	_ context.Context,
	tokenID int64,
	actorID string,
	isAdmin bool,
) error {
	repository.revokeCalls++
	repository.revokeID = tokenID
	repository.revokeActor = actorID
	repository.revokeAdmin = isAdmin
	return nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func TestIssueTokenStoresOnlySHA256DigestAndReturnsHighEntropySecret(t *testing.T) {
	repository := &fakePlatformTokenRepository{userExists: true, userRoles: []string{"platform_admin"}}
	tokenService, err := NewPlatformTokenService(repository)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(time.Hour)
	issued, err := tokenService.IssueToken(context.Background(), " admin ", " alice ", " build agent ", &expiresAt)
	if err != nil {
		t.Fatalf("IssueToken() error = %v", err)
	}
	if issued.ID != 17 || issued.UserID != "alice" || issued.Name != "build agent" {
		t.Fatalf("issued token metadata = %+v", issued)
	}
	if len(issued.Token) != len(platformTokenPrefix)+base64.RawURLEncoding.EncodedLen(32) ||
		!validPlatformTokenFormat(issued.Token) {
		t.Fatalf("token does not contain 256 bits of URL-safe random material: %q", issued.Token)
	}
	expectedHash := sha256.Sum256([]byte(issued.Token))
	if !equalBytes(repository.hash, expectedHash[:]) || len(repository.hash) != sha256.Size {
		t.Fatal("repository did not receive the SHA-256 digest")
	}
	if repository.userID != "alice" || repository.name != "build agent" ||
		repository.prefix != issued.Prefix || repository.expiresAt != &expiresAt {
		t.Fatalf("CreateToken() received unexpected values: %+v", repository)
	}
	if repository.actorID != "admin" {
		t.Fatalf("CreateToken() actor = %q, want the administrator who issued the token", repository.actorID)
	}
}

func TestIssueTokenRejectsInvalidInputsBeforePersistence(t *testing.T) {
	repository := &fakePlatformTokenRepository{}
	tokenService, err := NewPlatformTokenService(repository)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		userID    string
		name      string
		expiresAt *time.Time
	}{
		{userID: "", name: "valid"},
		{userID: "alice", name: ""},
		{userID: "alice", name: "valid", expiresAt: timePointer(time.Now().Add(-time.Second))},
	} {
		if _, err := tokenService.IssueToken(context.Background(), "admin", test.userID, test.name, test.expiresAt); err == nil {
			t.Errorf("IssueToken(%q, %q) expected validation error", test.userID, test.name)
		}
	}
	if repository.createCalls != 0 {
		t.Fatalf("CreateToken() calls = %d, want 0", repository.createCalls)
	}
}

func TestAuthenticateValidatesFormatAndRequiresIdentityRoles(t *testing.T) {
	repository := &fakePlatformTokenRepository{userExists: true, userRoles: []string{"standard_user"}}
	tokenService, err := NewPlatformTokenService(repository)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := tokenService.IssueToken(context.Background(), "alice", "alice", "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	repository.identity = AuthenticatedIdentity{
		UserID: "alice", TokenID: 17, Roles: []string{"standard_user"},
	}
	identity, err := tokenService.Authenticate(context.Background(), issued.Token)
	if err != nil {
		t.Fatalf("Authenticate(valid token) error = %v", err)
	}
	if identity.UserID != "alice" || identity.TokenID != 17 || len(identity.Roles) != 1 {
		t.Fatalf("identity = %+v", identity)
	}
	callsBeforeMalformed := repository.authCalls
	if _, err := tokenService.Authenticate(context.Background(), "not-a-token"); !errors.Is(err, ErrInvalidPlatformToken) {
		t.Fatalf("Authenticate(malformed) error = %v", err)
	}
	if repository.authCalls != callsBeforeMalformed {
		t.Fatal("repository was called for malformed token")
	}

	repository.identity.Roles = nil
	if _, err := tokenService.Authenticate(context.Background(), issued.Token); !errors.Is(err, ErrInvalidPlatformToken) {
		t.Fatalf("Authenticate(identity without roles) error = %v", err)
	}
}

func TestAuthenticatePropagatesRepositoryFailures(t *testing.T) {
	repository := &fakePlatformTokenRepository{
		authErr: errors.New("database unavailable"),
	}
	tokenService, err := NewPlatformTokenService(repository)
	if err != nil {
		t.Fatal(err)
	}
	raw := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if _, err := tokenService.Authenticate(context.Background(), platformTokenPrefix+raw); err == nil ||
		err.Error() != "database unavailable" {
		t.Fatalf("Authenticate() error = %v", err)
	}
}

func TestRevokeTokenAllowsOwnerAndPlatformAdmin(t *testing.T) {
	repository := &fakePlatformTokenRepository{}
	tokenService, err := NewPlatformTokenService(repository)
	if err != nil {
		t.Fatal(err)
	}
	if err := tokenService.RevokeToken(context.Background(), 9, AuthenticatedIdentity{
		UserID: "alice", Roles: []string{"standard_user"},
	}); err != nil {
		t.Fatalf("RevokeToken(owner) error = %v", err)
	}
	if repository.revokeID != 9 || repository.revokeActor != "alice" || repository.revokeAdmin {
		t.Fatalf("owner revoke arguments = %+v", repository)
	}
	if err := tokenService.RevokeToken(context.Background(), 10, AuthenticatedIdentity{
		UserID: "admin", Roles: []string{"platform_admin"},
	}); err != nil {
		t.Fatalf("RevokeToken(admin) error = %v", err)
	}
	if !repository.revokeAdmin {
		t.Fatal("platform admin revocation did not have admin scope")
	}
	if err := tokenService.RevokeToken(context.Background(), 0, AuthenticatedIdentity{UserID: "alice"}); err == nil {
		t.Fatal("RevokeToken() accepted a non-positive token ID")
	}
}

// TestIssueTokenRejectsRoleLessUser：无角色用户签发 token 必然无法登录
// （Authenticate 要求角色数 > 0），签发时刻必须拦截而不是让登录 401。
func TestIssueTokenRejectsRoleLessUser(t *testing.T) {
	repository := &fakePlatformTokenRepository{userExists: true}
	tokenService, err := NewPlatformTokenService(repository)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(time.Hour)
	if _, err := tokenService.IssueToken(context.Background(), "admin", "alice", "login", &expiresAt); !errors.Is(err, ErrPlatformUserNoRole) {
		t.Fatalf("IssueToken() error = %v, want ErrPlatformUserNoRole", err)
	}
	if repository.createCalls != 0 {
		t.Fatalf("CreateToken calls = %d, want 0 (no token persisted)", repository.createCalls)
	}

	// 用户不存在/停用 → 原有语义不变。
	missingService, err := NewPlatformTokenService(&fakePlatformTokenRepository{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missingService.IssueToken(context.Background(), "admin", "ghost", "login", &expiresAt); !errors.Is(err, ErrInvalidPlatformUser) {
		t.Fatalf("IssueToken(missing user) error = %v, want ErrInvalidPlatformUser", err)
	}

	// 有角色 → 正常签发。
	okService, err := NewPlatformTokenService(&fakePlatformTokenRepository{
		userExists: true, userRoles: []string{"approval_admin", "standard_user"},
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := okService.IssueToken(context.Background(), "admin", "alice", "login", &expiresAt)
	if err != nil || issued.ID != 17 {
		t.Fatalf("IssueToken() = (%+v, %v), want token 17 with no error", issued, err)
	}
}

// ---- A5：登录/会话语义的 SQL 锁 ----
//
// AuthenticateToken 的 WHERE 子句是「会话」的全部语义：token 未吊销
// （revoked_at IS NULL）、未过期（expires_at > NOW()）、用户仍活跃
//（is_active = TRUE）。任何一条被删掉，吊销 token / 到期 token / 停用
// 用户都会继续通过认证——fake driver 断言 SQL 文本与传参，把三条锁死。

func TestAuthenticateTokenSQLKeepsSessionSemantics(t *testing.T) {
	fake := &inventoryFakeDB{}
	fake.add("FROM platform_token AS token", []string{"id", "user_id"},
		[][]driver.Value{{int64(7), "alice"}})
	fake.add("mapping.user_id = $1", []string{"role_code"},
		[][]driver.Value{{"approval_admin"}})

	database := sql.OpenDB(fake)
	defer database.Close()
	repository, err := NewSQLPlatformTokenRepository(database)
	if err != nil {
		t.Fatalf("new repository: %v", err)
	}

	hash := HashPlatformToken("iamg_valid")
	identity, err := repository.AuthenticateToken(context.Background(), hash)
	if err != nil {
		t.Fatalf("AuthenticateToken: %v", err)
	}
	if identity.UserID != "alice" || identity.TokenID != 7 {
		t.Fatalf("identity = %#v", identity)
	}

	var authQuery string
	for _, query := range fake.queries {
		if strings.Contains(query, "FROM platform_token AS token") {
			authQuery = query
		}
	}
	for _, required := range []string{
		"revoked_at IS NULL",
		"expires_at IS NULL OR token.expires_at > NOW()",
		"platform_user.is_active = TRUE",
	} {
		if !strings.Contains(authQuery, required) {
			t.Errorf("AuthenticateToken SQL lost session condition %q:\n%s", required, authQuery)
		}
	}

	// last_used_at 更新不得“复活”已吊销的 token。
	var updateQuery string
	for _, query := range fake.queries {
		if strings.Contains(query, "UPDATE platform_token SET last_used_at") {
			updateQuery = query
		}
	}
	if updateQuery == "" {
		t.Fatalf("last_used_at update not executed; queries:\n%s", strings.Join(fake.queries, "\n"))
	}
	if !strings.Contains(updateQuery, "revoked_at IS NULL") {
		t.Errorf("last_used_at update must not touch revoked tokens:\n%s", updateQuery)
	}
}

// 查无此 token（吊销/过期/停用用户在 SQL 层都表现为 0 行）→ 统一映射为
// ErrInvalidPlatformToken，不泄露具体原因。
func TestAuthenticateTokenMapsNoRowsToInvalidToken(t *testing.T) {
	fake := &inventoryFakeDB{} // 无任何注册响应 → 0 行

	database := sql.OpenDB(fake)
	defer database.Close()
	repository, err := NewSQLPlatformTokenRepository(database)
	if err != nil {
		t.Fatalf("new repository: %v", err)
	}

	if _, err := repository.AuthenticateToken(context.Background(), HashPlatformToken("iamg_gone")); !errors.Is(err, ErrInvalidPlatformToken) {
		t.Fatalf("error = %v, want ErrInvalidPlatformToken", err)
	}
}
