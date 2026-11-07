package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"
)

// BootstrapAdminTokenFileName is the default file the first startup writes the
// bootstrap token to, next to the api executable's working directory.
const BootstrapAdminTokenFileName = "bootstrap-admin-token.txt"

// BootstrapAdminStore is the persistence the first-start bootstrap needs:
// deciding whether an administrator already exists, and creating/activating
// the default one when nobody can log in yet.
type BootstrapAdminStore interface {
	CountActiveAdmins(ctx context.Context) (int, error)
	EnsureAdminUser(ctx context.Context, userID, displayName string) error
}

// SQLBootstrapAdminStore implements BootstrapAdminStore on the platform tables.
type SQLBootstrapAdminStore struct {
	db *sql.DB
}

func NewSQLBootstrapAdminStore(db *sql.DB) (*SQLBootstrapAdminStore, error) {
	if db == nil {
		return nil, errors.New("bootstrap admin database must not be nil")
	}
	return &SQLBootstrapAdminStore{db: db}, nil
}

// CountActiveAdmins reports how many active platform users hold the
// platform_admin role. Any one of them being able to log in means the install
// is past its first start and the bootstrap must not mint new credentials.
func (store *SQLBootstrapAdminStore) CountActiveAdmins(ctx context.Context) (int, error) {
	var admins int
	err := store.db.QueryRowContext(ctx, `SELECT COUNT(*)
		FROM user_role_mapping m
		JOIN platform_user u ON u.user_id = m.user_id AND u.is_active = TRUE
		JOIN platform_role r ON r.id = m.role_id AND r.role_code = 'platform_admin'`,
	).Scan(&admins)
	if err != nil {
		return 0, fmt.Errorf("count active platform admins: %w", err)
	}
	return admins, nil
}

// EnsureAdminUser creates or activates userID and grants platform_admin when
// the role is missing. Existing roles are preserved: this is a bootstrap for a
// locked-out install, not a permission reset.
func (store *SQLBootstrapAdminStore) EnsureAdminUser(ctx context.Context, userID, displayName string) error {
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin bootstrap admin transaction: %w", err)
	}
	defer transaction.Rollback()

	// 'system' 不是真实登录人，但 user_role_mapping.assigned_by 与
	// platform_token.created_by 的外键都指向 platform_user(user_id)——
	// 没有这行占位，授权和签发 token 都会以 SQLSTATE 23503 失败。
	// is_active=FALSE 保证它永远无法登录，也不会被 CountActiveAdmins 计入。
	if _, err := transaction.ExecContext(ctx, `INSERT INTO platform_user
		(user_id, display_name, is_active, created_at, updated_at)
		VALUES ('system', '系统自举', FALSE, NOW(), NOW())
		ON CONFLICT (user_id) DO NOTHING`,
	); err != nil {
		return fmt.Errorf("upsert bootstrap system actor: %w", err)
	}

	if _, err := transaction.ExecContext(ctx, `INSERT INTO platform_user
		(user_id, display_name, is_active, created_at, updated_at)
		VALUES ($1, $2, TRUE, NOW(), NOW())
		ON CONFLICT (user_id) DO UPDATE SET is_active = TRUE, updated_at = NOW()`,
		userID, displayName,
	); err != nil {
		return fmt.Errorf("upsert bootstrap admin user: %w", err)
	}
	result, err := transaction.ExecContext(ctx, `INSERT INTO user_role_mapping (user_id, role_id, assigned_by)
		SELECT $1, role.id, 'system' FROM platform_role AS role
		WHERE role.role_code = 'platform_admin'
		ON CONFLICT (user_id, role_id) DO NOTHING`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("grant bootstrap platform_admin: %w", err)
	}
	// platform_role 缺行（迁移没跑/种子没种）时 INSERT SELECT 静默插 0 行，
	// 之后 IssueToken 的 UserAuthz 守卫只会给出无解释的 no-role 错误——在这里
	// 就把真实原因暴露出来。
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("verify bootstrap platform_admin grant: %w", err)
	}
	if affected == 0 {
		var mapped int
		if err := transaction.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM user_role_mapping m
			 JOIN platform_role r ON r.id = m.role_id AND r.role_code = 'platform_admin'
			 WHERE m.user_id = $1`, userID,
		).Scan(&mapped); err != nil {
			return fmt.Errorf("verify bootstrap platform_admin mapping: %w", err)
		}
		if mapped == 0 {
			return errors.New("platform_role has no 'platform_admin' row; run migrations before starting the API")
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit bootstrap admin: %w", err)
	}
	return nil
}

// BootstrapAdminOptions controls the first-start bootstrap. Zero fields fall
// back to the documented defaults.
type BootstrapAdminOptions struct {
	// UserID of the default administrator (default "admin").
	UserID string
	// DisplayName written when the user has to be created (default 平台管理员).
	DisplayName string
	// TTL of the bootstrap token (default 120 days). Tokens outlive this and
	// must be revoked after the first login.
	TTL time.Duration
	// TokenFile is where the plaintext token is written (default
	// bootstrap-admin-token.txt in the working directory). Empty disables the
	// file entirely — the secret then exists only in the returned result.
	TokenFile string
}

// BootstrapAdminResult reports what the first-start bootstrap did.
type BootstrapAdminResult struct {
	// Skipped is true when an active platform_admin already exists; no new
	// credentials are minted on any later start.
	Skipped bool
	Reason  string
	UserID  string
	// Token is nil unless a fresh token was issued this start.
	Token     *IssuedPlatformToken
	TokenFile string
}

// BootstrapAdmin makes a brand-new installation loggable-in without the CLI:
// when no active platform_admin exists it creates/activates the default admin,
// grants the role and issues one token, written to TokenFile. Any later start
// (an admin exists) is a no-op, so restarting never mints new credentials. A
// lost token with an intact admin is the CLI's job: platform-token
// -bootstrap-admin.
func BootstrapAdmin(
	ctx context.Context,
	store BootstrapAdminStore,
	tokenService *PlatformTokenService,
	options BootstrapAdminOptions,
) (BootstrapAdminResult, error) {
	if store == nil {
		return BootstrapAdminResult{}, errors.New("bootstrap admin store must not be nil")
	}
	if tokenService == nil {
		return BootstrapAdminResult{}, errors.New("platform token service must not be nil")
	}
	userID := options.UserID
	if userID == "" {
		userID = "admin"
	}
	displayName := options.DisplayName
	if displayName == "" {
		displayName = "平台管理员"
	}
	ttl := options.TTL
	if ttl <= 0 {
		ttl = 120 * 24 * time.Hour
	}

	admins, err := store.CountActiveAdmins(ctx)
	if err != nil {
		return BootstrapAdminResult{}, err
	}
	if admins > 0 {
		return BootstrapAdminResult{
			Skipped: true,
			Reason:  fmt.Sprintf("%d active platform_admin user(s) exist", admins),
			UserID:  userID,
		}, nil
	}

	if err := store.EnsureAdminUser(ctx, userID, displayName); err != nil {
		return BootstrapAdminResult{}, err
	}
	expiresAt := time.Now().UTC().Add(ttl)
	// actorID "system": the grant and the token both come from the startup
	// itself, not from any logged-in human.
	issued, err := tokenService.IssueToken(ctx, "system", userID, "bootstrap-admin", &expiresAt)
	if err != nil {
		return BootstrapAdminResult{}, fmt.Errorf("issue bootstrap admin token: %w", err)
	}
	result := BootstrapAdminResult{UserID: userID, Token: &issued}

	if options.TokenFile != "" {
		if err := writeBootstrapTokenFile(options.TokenFile, userID, issued); err != nil {
			return BootstrapAdminResult{}, err
		}
		result.TokenFile = options.TokenFile
	}
	return result, nil
}

// writeBootstrapTokenFile puts the plaintext token in one place with the most
// restrictive mode we can ask for, so it can be deleted after the first login
// instead of living on in rotated logs.
func writeBootstrapTokenFile(path, userID string, issued IssuedPlatformToken) error {
	expires := "never"
	if issued.ExpiresAt != nil {
		expires = issued.ExpiresAt.Format(time.RFC3339)
	}
	content := fmt.Sprintf(`# Cloud IAM Governance Hub · 首次启动自举生成的管理员凭证
# 生成时间: %s
# 用户: %s
# 有效期至: %s
# 用法: 登录页粘贴下面的 token（即 Authorization: Bearer <token>）
# 首次登录后请尽快吊销本枚 token（设置 → Token 管理），然后删除本文件。

%s
`, time.Now().UTC().Format(time.RFC3339), userID, expires, issued.Token)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write bootstrap admin token file %s: %w", path, err)
	}
	return nil
}
