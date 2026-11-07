package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const platformTokenPrefix = "iamg_"

var (
	ErrInvalidPlatformToken = errors.New("invalid or inactive platform token")
	ErrInvalidPlatformUser  = errors.New("platform user is missing or inactive")
	// ErrPlatformUserNoRole：用户存在且在职但没有任何平台角色。此时签发的
	// token 会在 Authenticate（len(roles)==0）被拒，登录必然 401 且无法
	// 自行解释——把拦截提前到签发时刻，报错落在管理员能看见的地方。
	ErrPlatformUserNoRole = errors.New("platform user has no platform role")
)

type AuthenticatedIdentity struct {
	UserID  string
	TokenID int64
	Roles   []string
}

type PlatformTokenRepository interface {
	CreateToken(ctx context.Context, actorID, userID, name, tokenPrefix string, tokenHash []byte, expiresAt *time.Time) (int64, error)
	AuthenticateToken(ctx context.Context, tokenHash []byte) (AuthenticatedIdentity, error)
	RevokeToken(ctx context.Context, tokenID int64, actorID string, isAdmin bool) error
	ListTokens(ctx context.Context, userID string) ([]PlatformTokenInfo, error)
	// UserAuthz resolves whether the user exists and is active, plus its
	// current role codes. IssueToken uses it to reject a role-less user at
	// issuance time instead of letting the token fail authentication later.
	UserAuthz(ctx context.Context, userID string) (exists bool, roles []string, err error)
}

// PlatformTokenInfo is the metadata of an issued token. The secret itself is
// never stored (only its SHA-256 digest) and is shown once at issuance.
type PlatformTokenInfo struct {
	ID         int64      `json:"id"`
	UserID     string     `json:"user_id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

type PlatformTokenService struct {
	repository PlatformTokenRepository
}

type IssuedPlatformToken struct {
	ID        int64      `json:"id"`
	UserID    string     `json:"user_id"`
	Name      string     `json:"name"`
	Prefix    string     `json:"prefix"`
	Token     string     `json:"token"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func NewPlatformTokenService(repository PlatformTokenRepository) (*PlatformTokenService, error) {
	if repository == nil {
		return nil, errors.New("platform token repository must not be nil")
	}
	return &PlatformTokenService{repository: repository}, nil
}

// IssueToken returns the secret once and stores only its SHA-256 digest.
// actorID is who asked for the token: the token owner when someone issues a
// token for themselves, the administrator when one issues it for someone else
// (the audit event records the actor, not the owner).
func (service *PlatformTokenService) IssueToken(
	ctx context.Context,
	actorID string,
	userID string,
	name string,
	expiresAt *time.Time,
) (IssuedPlatformToken, error) {
	if service == nil || service.repository == nil {
		return IssuedPlatformToken{}, errors.New("platform token service is not configured")
	}
	userID = strings.TrimSpace(userID)
	name = strings.TrimSpace(name)
	actorID = strings.TrimSpace(actorID)
	if userID == "" || len(userID) > 128 {
		return IssuedPlatformToken{}, errors.New("platform user ID must contain 1 to 128 characters")
	}
	if name == "" || len(name) > 128 {
		return IssuedPlatformToken{}, errors.New("token name must contain 1 to 128 characters")
	}
	if expiresAt != nil && !expiresAt.After(time.Now()) {
		return IssuedPlatformToken{}, errors.New("token expiry must be in the future")
	}
	if actorID == "" {
		actorID = userID
	}

	// 签发前校验：用户必须存在、在职且至少有一个平台角色，否则这枚 token
	// 注定无法登录（Authenticate 要求 len(roles)>0），报错却只会是无解释的
	// 401。提前拦截把问题暴露在签发动作上，管理员当场就能修。
	exists, roles, err := service.repository.UserAuthz(ctx, userID)
	if err != nil {
		return IssuedPlatformToken{}, fmt.Errorf("resolve platform user authz: %w", err)
	}
	if !exists {
		return IssuedPlatformToken{}, ErrInvalidPlatformUser
	}
	if len(roles) == 0 {
		return IssuedPlatformToken{}, ErrPlatformUserNoRole
	}

	var randomBytes [32]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return IssuedPlatformToken{}, fmt.Errorf("generate platform token: %w", err)
	}
	token := platformTokenPrefix + base64.RawURLEncoding.EncodeToString(randomBytes[:])
	digest := sha256.Sum256([]byte(token))
	tokenPrefix := token[:len(platformTokenPrefix)+8]
	tokenID, err := service.repository.CreateToken(ctx, actorID, userID, name, tokenPrefix, digest[:], expiresAt)
	if err != nil {
		return IssuedPlatformToken{}, fmt.Errorf("persist platform token: %w", err)
	}
	return IssuedPlatformToken{
		ID: tokenID, UserID: userID, Name: name, Prefix: tokenPrefix,
		Token: token, ExpiresAt: expiresAt,
	}, nil
}

// ListTokens returns the token metadata for one user (or all users when
// userID is empty). Secrets are never part of the result.
func (service *PlatformTokenService) ListTokens(
	ctx context.Context,
	userID string,
) ([]PlatformTokenInfo, error) {
	if service == nil || service.repository == nil {
		return nil, errors.New("platform token service is not configured")
	}
	return service.repository.ListTokens(ctx, strings.TrimSpace(userID))
}

func (service *PlatformTokenService) Authenticate(
	ctx context.Context,
	token string,
) (AuthenticatedIdentity, error) {
	if service == nil || service.repository == nil {
		return AuthenticatedIdentity{}, errors.New("platform token service is not configured")
	}
	if !validPlatformTokenFormat(token) {
		return AuthenticatedIdentity{}, ErrInvalidPlatformToken
	}
	digest := sha256.Sum256([]byte(token))
	identity, err := service.repository.AuthenticateToken(ctx, digest[:])
	if err != nil {
		return AuthenticatedIdentity{}, err
	}
	if identity.UserID == "" || identity.TokenID <= 0 || len(identity.Roles) == 0 {
		return AuthenticatedIdentity{}, ErrInvalidPlatformToken
	}
	return identity, nil
}

func (service *PlatformTokenService) RevokeToken(
	ctx context.Context,
	tokenID int64,
	actor AuthenticatedIdentity,
) error {
	if service == nil || service.repository == nil {
		return errors.New("platform token service is not configured")
	}
	if tokenID <= 0 || strings.TrimSpace(actor.UserID) == "" {
		return errors.New("token ID and authenticated actor are required")
	}
	isAdmin := false
	for _, role := range actor.Roles {
		if role == "platform_admin" {
			isAdmin = true
			break
		}
	}
	return service.repository.RevokeToken(ctx, tokenID, actor.UserID, isAdmin)
}

func HashPlatformToken(token string) []byte {
	digest := sha256.Sum256([]byte(token))
	return digest[:]
}

func validPlatformTokenFormat(token string) bool {
	if !strings.HasPrefix(token, platformTokenPrefix) {
		return false
	}
	encoded := strings.TrimPrefix(token, platformTokenPrefix)
	if len(encoded) != base64.RawURLEncoding.EncodedLen(32) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil && len(decoded) == 32
}

type SQLPlatformTokenRepository struct {
	db *sql.DB
}

func NewSQLPlatformTokenRepository(db *sql.DB) (*SQLPlatformTokenRepository, error) {
	if db == nil {
		return nil, errors.New("database connection must not be nil")
	}
	return &SQLPlatformTokenRepository{db: db}, nil
}

func (repository *SQLPlatformTokenRepository) CreateToken(
	ctx context.Context,
	actorID, userID, name, tokenPrefix string,
	tokenHash []byte,
	expiresAt *time.Time,
) (int64, error) {
	if repository == nil || repository.db == nil {
		return 0, errors.New("platform token database must not be nil")
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin token creation transaction: %w", err)
	}
	defer transaction.Rollback()

	var tokenID int64
	err = transaction.QueryRowContext(ctx, `INSERT INTO platform_token
		(user_id, token_hash, token_prefix, token_name, expires_at, created_by, created_at)
		SELECT user_id, $3, $4, $5, $6, $2, NOW()
		FROM platform_user WHERE user_id = $1 AND is_active = TRUE
		RETURNING id`, userID, actorID, tokenHash, tokenPrefix, name, expiresAt,
	).Scan(&tokenID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrInvalidPlatformUser
	}
	if err != nil {
		return 0, fmt.Errorf("insert platform token: %w", err)
	}
	metadata, err := json.Marshal(map[string]interface{}{
		"token_id": tokenID, "token_prefix": tokenPrefix, "token_name": name,
		"token_owner_id": userID,
	})
	if err != nil {
		return 0, fmt.Errorf("encode token audit metadata: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO iam_audit_event
		(actor_id, action, resource_type, resource_id, outcome, metadata, occurred_at)
		VALUES ($1, 'PLATFORM_TOKEN_CREATED', 'platform_token', $2, 'SUCCESS', $3::jsonb, NOW())`,
		actorID, fmt.Sprint(tokenID), string(metadata),
	); err != nil {
		return 0, fmt.Errorf("audit platform token creation: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return 0, fmt.Errorf("commit token creation: %w", err)
	}
	return tokenID, nil
}

// UserAuthz reports whether the user exists and is active, plus its current
// role codes. Used by IssueToken to reject a role-less user at issuance time.
func (repository *SQLPlatformTokenRepository) UserAuthz(
	ctx context.Context,
	userID string,
) (bool, []string, error) {
	if repository == nil || repository.db == nil {
		return false, nil, errors.New("platform token database must not be nil")
	}
	var exists bool
	if err := repository.db.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM platform_user WHERE user_id = $1 AND is_active = TRUE)`, userID,
	).Scan(&exists); err != nil {
		return false, nil, fmt.Errorf("check platform user existence: %w", err)
	}
	if !exists {
		return false, nil, nil
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT r.role_code
		FROM user_role_mapping m
		JOIN platform_role r ON r.id = m.role_id
		WHERE m.user_id = $1
		ORDER BY r.role_code`, userID)
	if err != nil {
		return false, nil, fmt.Errorf("list platform user roles: %w", err)
	}
	defer rows.Close()
	roles := make([]string, 0)
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return false, nil, fmt.Errorf("scan platform user role: %w", err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return false, nil, fmt.Errorf("iterate platform user roles: %w", err)
	}
	return true, roles, nil
}

// ListTokens returns token metadata (never a secret) for one user or for all
// users when userID is empty.
func (repository *SQLPlatformTokenRepository) ListTokens(
	ctx context.Context,
	userID string,
) ([]PlatformTokenInfo, error) {
	if repository == nil || repository.db == nil {
		return nil, errors.New("platform token database must not be nil")
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT id, user_id, token_name, token_prefix,
		expires_at, revoked_at, last_used_at, created_at
		FROM platform_token
		WHERE ($1 = '' OR user_id = $1)
		ORDER BY created_at DESC, id DESC
		LIMIT 500`, userID)
	if err != nil {
		return nil, fmt.Errorf("list platform tokens: %w", err)
	}
	defer rows.Close()
	tokens := make([]PlatformTokenInfo, 0)
	for rows.Next() {
		var token PlatformTokenInfo
		if err := rows.Scan(&token.ID, &token.UserID, &token.Name, &token.Prefix,
			&token.ExpiresAt, &token.RevokedAt, &token.LastUsedAt, &token.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan platform token: %w", err)
		}
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate platform tokens: %w", err)
	}
	return tokens, nil
}

func (repository *SQLPlatformTokenRepository) AuthenticateToken(
	ctx context.Context,
	tokenHash []byte,
) (AuthenticatedIdentity, error) {
	if repository == nil || repository.db == nil {
		return AuthenticatedIdentity{}, errors.New("platform token database must not be nil")
	}
	var identity AuthenticatedIdentity
	err := repository.db.QueryRowContext(ctx, `SELECT token.id, platform_user.user_id
		FROM platform_token AS token
		JOIN platform_user ON platform_user.user_id = token.user_id
		WHERE token.token_hash = $1 AND token.revoked_at IS NULL
			AND (token.expires_at IS NULL OR token.expires_at > NOW())
			AND platform_user.is_active = TRUE`, tokenHash,
	).Scan(&identity.TokenID, &identity.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthenticatedIdentity{}, ErrInvalidPlatformToken
	}
	if err != nil {
		return AuthenticatedIdentity{}, fmt.Errorf("lookup platform token: %w", err)
	}

	rows, err := repository.db.QueryContext(ctx, `SELECT role.role_code
		FROM user_role_mapping AS mapping
		JOIN platform_role AS role ON role.id = mapping.role_id
		WHERE mapping.user_id = $1 ORDER BY role.role_code`, identity.UserID)
	if err != nil {
		return AuthenticatedIdentity{}, fmt.Errorf("load platform roles: %w", err)
	}
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			rows.Close()
			return AuthenticatedIdentity{}, fmt.Errorf("scan platform role: %w", err)
		}
		identity.Roles = append(identity.Roles, role)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return AuthenticatedIdentity{}, fmt.Errorf("iterate platform roles: %w", err)
	}
	if err := rows.Close(); err != nil {
		return AuthenticatedIdentity{}, fmt.Errorf("close platform role rows: %w", err)
	}
	if len(identity.Roles) == 0 {
		return AuthenticatedIdentity{}, ErrInvalidPlatformToken
	}
	if _, err := repository.db.ExecContext(ctx,
		`UPDATE platform_token SET last_used_at = NOW()
		 WHERE id = $1 AND revoked_at IS NULL`, identity.TokenID,
	); err != nil {
		return AuthenticatedIdentity{}, fmt.Errorf("update platform token last-used timestamp: %w", err)
	}
	return identity, nil
}

func (repository *SQLPlatformTokenRepository) RevokeToken(
	ctx context.Context,
	tokenID int64,
	actorID string,
	isAdmin bool,
) error {
	if repository == nil || repository.db == nil {
		return errors.New("platform token database must not be nil")
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin token revocation transaction: %w", err)
	}
	defer transaction.Rollback()

	var ownerID string
	err = transaction.QueryRowContext(ctx, `UPDATE platform_token
		SET revoked_at = NOW()
		WHERE id = $1 AND revoked_at IS NULL
			AND (user_id = $2 OR $3 = TRUE)
		RETURNING user_id`, tokenID, actorID, isAdmin,
	).Scan(&ownerID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidPlatformToken
	}
	if err != nil {
		return fmt.Errorf("revoke platform token: %w", err)
	}
	metadata, err := json.Marshal(map[string]interface{}{
		"token_id": tokenID, "token_owner_id": ownerID,
	})
	if err != nil {
		return fmt.Errorf("encode token revocation audit metadata: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO iam_audit_event
		(actor_id, action, resource_type, resource_id, outcome, metadata, occurred_at)
		VALUES ($1, 'PLATFORM_TOKEN_REVOKED', 'platform_token', $2, 'SUCCESS', $3::jsonb, NOW())`,
		actorID, fmt.Sprint(tokenID), string(metadata),
	); err != nil {
		return fmt.Errorf("audit platform token revocation: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit token revocation: %w", err)
	}
	return nil
}

var _ PlatformTokenRepository = (*SQLPlatformTokenRepository)(nil)
