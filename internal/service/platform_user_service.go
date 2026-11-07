package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
)

// PlatformRoleCodes are the roles a platform user can hold. The database
// enforces the same set (platform_role_code_check).
var PlatformRoleCodes = []string{"platform_admin", "approval_admin", "standard_user"}

// ErrPlatformUserNotFound marks a user that does not exist.
var ErrPlatformUserNotFound = errors.New("platform user not found")

// PlatformUser is a platform identity together with its roles.
type PlatformUser struct {
	UserID      string    `json:"user_id"`
	DisplayName string    `json:"display_name"`
	Email       *string   `json:"email,omitempty"`
	IsActive    bool      `json:"is_active"`
	Roles       []string  `json:"roles"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// UpsertPlatformUser describes the desired state of one platform user.
type UpsertPlatformUser struct {
	UserID      string   `json:"user_id"`
	DisplayName string   `json:"display_name"`
	Email       string   `json:"email,omitempty"`
	IsActive    *bool    `json:"is_active,omitempty"`
	Roles       []string `json:"roles"`
}

// PlatformUserRepository persists platform users and their role mappings.
type PlatformUserRepository interface {
	ListUsers(ctx context.Context) ([]PlatformUser, error)
	UpsertUser(ctx context.Context, user UpsertPlatformUser, actorID string) error
	FindUser(ctx context.Context, userID string) (PlatformUser, error)
}

// PlatformUserService manages platform users for administrators.
type PlatformUserService struct {
	repository PlatformUserRepository
	tokens     *PlatformTokenService
}

func NewPlatformUserService(
	repository PlatformUserRepository,
	tokens *PlatformTokenService,
) (*PlatformUserService, error) {
	if repository == nil {
		return nil, errors.New("platform user repository must not be nil")
	}
	if tokens == nil {
		return nil, errors.New("platform token service must not be nil")
	}
	return &PlatformUserService{repository: repository, tokens: tokens}, nil
}

// ListUsers returns every platform user with its roles.
func (service *PlatformUserService) ListUsers(ctx context.Context) ([]PlatformUser, error) {
	if service == nil || service.repository == nil {
		return nil, errors.New("platform user service is not configured")
	}
	return service.repository.ListUsers(ctx)
}

// UpsertUser creates a platform user or replaces its display name, e-mail,
// active flag and role set. Roles are replaced, not merged: an administrator
// sets the access a person has, and the previous set is dropped.
func (service *PlatformUserService) UpsertUser(
	ctx context.Context,
	user UpsertPlatformUser,
	actorID string,
) error {
	if service == nil || service.repository == nil {
		return errors.New("platform user service is not configured")
	}
	user.UserID = strings.TrimSpace(user.UserID)
	user.DisplayName = strings.TrimSpace(user.DisplayName)
	user.Email = strings.TrimSpace(user.Email)
	if user.UserID == "" || len(user.UserID) > 128 {
		return errors.New("platform user ID must contain 1 to 128 characters")
	}
	if user.DisplayName == "" || len(user.DisplayName) > 256 {
		return errors.New("display name must contain 1 to 256 characters")
	}
	if user.Email != "" {
		if len(user.Email) > 320 {
			return errors.New("e-mail must not exceed 320 characters")
		}
		if _, err := mail.ParseAddress(user.Email); err != nil {
			return errors.New("e-mail address is not valid")
		}
	}
	roles, err := normalizePlatformRoles(user.Roles)
	if err != nil {
		return err
	}
	if len(roles) == 0 {
		return errors.New("at least one role is required")
	}
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return errors.New("authenticated actor is required")
	}
	// 未提交 is_active 时保留原值：一次局部更新不该把已停用的账号悄悄启用。
	isActive := true
	if user.IsActive != nil {
		isActive = *user.IsActive
	} else {
		existing, findErr := service.repository.FindUser(ctx, user.UserID)
		switch {
		case errors.Is(findErr, ErrPlatformUserNotFound):
			isActive = true
		case findErr != nil:
			return findErr
		default:
			isActive = existing.IsActive
		}
	}
	// 不允许把自己停用或摘掉自己的平台管理员角色——否则会出现无人能进平台的死锁。
	if actorID == user.UserID && !isActive {
		return errors.New("you cannot deactivate your own account")
	}
	if actorID == user.UserID && !containsPlatformRole(roles, "platform_admin") {
		return errors.New("you cannot remove your own platform_admin role")
	}
	user.IsActive = &isActive
	user.Roles = roles
	return service.repository.UpsertUser(ctx, user, actorID)
}

// IssueToken issues a login token for a user. The secret is returned once;
// only its digest is stored.
func (service *PlatformUserService) IssueToken(
	ctx context.Context,
	actorID string,
	userID string,
	name string,
	expiresAt *time.Time,
) (IssuedPlatformToken, error) {
	if service == nil || service.tokens == nil {
		return IssuedPlatformToken{}, errors.New("platform user service is not configured")
	}
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return IssuedPlatformToken{}, errors.New("authenticated actor is required")
	}
	return service.tokens.IssueToken(ctx, actorID, userID, name, expiresAt)
}

// ListTokens returns the token metadata of one user (or of all users when
// userID is empty).
func (service *PlatformUserService) ListTokens(
	ctx context.Context,
	userID string,
) ([]PlatformTokenInfo, error) {
	if service == nil || service.tokens == nil {
		return nil, errors.New("platform user service is not configured")
	}
	return service.tokens.ListTokens(ctx, userID)
}

func normalizePlatformRoles(roles []string) ([]string, error) {
	seen := make(map[string]struct{}, len(roles))
	normalized := make([]string, 0, len(roles))
	for _, role := range roles {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		if !containsPlatformRole(PlatformRoleCodes, role) {
			return nil, fmt.Errorf("unknown platform role %q; supported roles are %s",
				role, strings.Join(PlatformRoleCodes, ", "))
		}
		if _, exists := seen[role]; exists {
			continue
		}
		seen[role] = struct{}{}
		normalized = append(normalized, role)
	}
	return normalized, nil
}

func containsPlatformRole(roles []string, role string) bool {
	for _, candidate := range roles {
		if candidate == role {
			return true
		}
	}
	return false
}

// SQLPlatformUserRepository persists platform users in PostgreSQL.
type SQLPlatformUserRepository struct {
	db *sql.DB
}

func NewSQLPlatformUserRepository(db *sql.DB) (*SQLPlatformUserRepository, error) {
	if db == nil {
		return nil, errors.New("database connection must not be nil")
	}
	return &SQLPlatformUserRepository{db: db}, nil
}

func (repository *SQLPlatformUserRepository) ListUsers(ctx context.Context) ([]PlatformUser, error) {
	if repository == nil || repository.db == nil {
		return nil, errors.New("platform user database must not be nil")
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT pu.user_id, pu.display_name, pu.email,
		pu.is_active, pu.created_at, pu.updated_at,
		COALESCE(jsonb_agg(role.role_code) FILTER (WHERE role.role_code IS NOT NULL), '[]'::jsonb)
		FROM platform_user AS pu
		LEFT JOIN user_role_mapping AS mapping ON mapping.user_id = pu.user_id
		LEFT JOIN platform_role AS role ON role.id = mapping.role_id
		GROUP BY pu.user_id, pu.display_name, pu.email, pu.is_active, pu.created_at, pu.updated_at
		ORDER BY pu.user_id`)
	if err != nil {
		return nil, fmt.Errorf("list platform users: %w", err)
	}
	defer rows.Close()
	users := make([]PlatformUser, 0)
	for rows.Next() {
		var user PlatformUser
		var rolesJSON []byte
		if err := rows.Scan(&user.UserID, &user.DisplayName, &user.Email, &user.IsActive,
			&user.CreatedAt, &user.UpdatedAt, &rolesJSON); err != nil {
			return nil, fmt.Errorf("scan platform user: %w", err)
		}
		user.Roles = decodePlatformRoles(rolesJSON)
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate platform users: %w", err)
	}
	return users, nil
}

func (repository *SQLPlatformUserRepository) FindUser(
	ctx context.Context,
	userID string,
) (PlatformUser, error) {
	if repository == nil || repository.db == nil {
		return PlatformUser{}, errors.New("platform user database must not be nil")
	}
	var user PlatformUser
	var rolesJSON []byte
	err := repository.db.QueryRowContext(ctx, `SELECT pu.user_id, pu.display_name, pu.email,
		pu.is_active, pu.created_at, pu.updated_at,
		COALESCE(jsonb_agg(role.role_code) FILTER (WHERE role.role_code IS NOT NULL), '[]'::jsonb)
		FROM platform_user AS pu
		LEFT JOIN user_role_mapping AS mapping ON mapping.user_id = pu.user_id
		LEFT JOIN platform_role AS role ON role.id = mapping.role_id
		WHERE pu.user_id = $1
		GROUP BY pu.user_id, pu.display_name, pu.email, pu.is_active, pu.created_at, pu.updated_at`,
		userID,
	).Scan(&user.UserID, &user.DisplayName, &user.Email, &user.IsActive,
		&user.CreatedAt, &user.UpdatedAt, &rolesJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return PlatformUser{}, ErrPlatformUserNotFound
	}
	if err != nil {
		return PlatformUser{}, fmt.Errorf("load platform user: %w", err)
	}
	user.Roles = decodePlatformRoles(rolesJSON)
	return user, nil
}

// decodePlatformRoles decodes the role list aggregated as JSONB. The database
// driver hands arrays back as text, so roles travel as JSON like the rest of
// the platform's array columns.
func decodePlatformRoles(raw []byte) []string {
	roles := make([]string, 0)
	if len(raw) == 0 {
		return roles
	}
	if err := json.Unmarshal(raw, &roles); err != nil {
		return []string{}
	}
	return roles
}

func (repository *SQLPlatformUserRepository) UpsertUser(
	ctx context.Context,
	user UpsertPlatformUser,
	actorID string,
) error {
	if repository == nil || repository.db == nil {
		return errors.New("platform user database must not be nil")
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin platform user transaction: %w", err)
	}
	defer transaction.Rollback()

	var email any
	if user.Email != "" {
		email = user.Email
	}
	isActive := true
	if user.IsActive != nil {
		isActive = *user.IsActive
	}
	action := "PLATFORM_USER_UPDATED"
	if _, err := transaction.ExecContext(ctx, `INSERT INTO platform_user
		(user_id, display_name, email, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (user_id) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			email = EXCLUDED.email,
			is_active = EXCLUDED.is_active,
			updated_at = NOW()`,
		user.UserID, user.DisplayName, email, isActive,
	); err != nil {
		return fmt.Errorf("upsert platform user: %w", err)
	}
	// 角色按「设置」语义替换：先清旧映射，再挂新角色。
	if _, err := transaction.ExecContext(ctx,
		`DELETE FROM user_role_mapping WHERE user_id = $1`, user.UserID); err != nil {
		return fmt.Errorf("clear platform user roles: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO user_role_mapping (user_id, role_id, assigned_by)
		SELECT $1, role.id, $2 FROM platform_role AS role WHERE role.role_code = ANY($3)`,
		user.UserID, actorID, user.Roles,
	); err != nil {
		return fmt.Errorf("assign platform user roles: %w", err)
	}
	metadata, err := json.Marshal(map[string]interface{}{
		"user_id": user.UserID, "roles": user.Roles, "is_active": isActive,
	})
	if err != nil {
		return fmt.Errorf("encode platform user audit metadata: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO iam_audit_event
		(actor_id, action, resource_type, resource_id, outcome, metadata, occurred_at)
		VALUES ($1, $2, 'platform_user', $3, 'SUCCESS', $4::jsonb, NOW())`,
		actorID, action, user.UserID, string(metadata),
	); err != nil {
		return fmt.Errorf("audit platform user change: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit platform user change: %w", err)
	}
	return nil
}

var _ PlatformUserRepository = (*SQLPlatformUserRepository)(nil)
