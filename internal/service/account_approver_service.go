package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Account approver binding errors. The handler maps them to HTTP statuses.
var (
	// ErrAccountApproverAccountNotFound means the target aws_account row does
	// not exist (binding is keyed by the database id, not the 12-digit
	// account number).
	ErrAccountApproverAccountNotFound = errors.New("AWS account not found")
	// ErrAccountApproverInvalidUser wraps a set of user ids that are not
	// active platform_admin/approval_admin users and therefore can never
	// decide a ticket (see ListAvailableApprovers). Binding them would create
	// tickets that are permanently stuck.
	ErrAccountApproverInvalidUser = errors.New("user is not an active platform_admin or approval_admin")
)

// approverRoleCodes mirrors the role filter in
// SQLTicketRepository.ListAvailableApprovers — the binding write path MUST
// accept exactly the users the read path resolves, or AUTO/MANUAL silently
// diverge.
var approverRoleCodes = []string{"platform_admin", "approval_admin"}

// AccountApproverBinding is one aws_account_approver row enriched with the
// bound user's profile for display.
type AccountApproverBinding struct {
	AccountID   int64     `json:"account_id"`
	UserID      string    `json:"user_id"`
	DisplayName string    `json:"display_name"`
	Email       *string   `json:"email,omitempty"`
	IsActive    bool      `json:"is_active"`
	Roles       []string  `json:"roles"`
	CreatedAt   time.Time `json:"created_at"`
}

// AccountApproverCandidate is an eligible approver plus whether it is already
// bound to the account. One query feeds the settings picker: preselect the
// bound ones, offer the rest.
type AccountApproverCandidate struct {
	UserID      string  `json:"user_id"`
	DisplayName string  `json:"display_name"`
	Email       *string `json:"email,omitempty"`
	Bound       bool    `json:"bound"`
}

// ApproverAccountSummary is one account where a user is still bound as an
// approver — shown when deactivating or demoting the user (A9③乙: without
// this warning the accounts silently lose their approval chain).
type ApproverAccountSummary struct {
	AccountDBID int64     `json:"account_db_id"`
	AccountNo   string    `json:"account_no"`
	AccountName *string   `json:"account_name,omitempty"`
	BoundAt     time.Time `json:"bound_at"`
}

// AccountApproverService manages the aws_account_approver binding table —
// until now it only had read paths, which made every freshly onboarded
// account unable to enter the approval flow (A9).
type AccountApproverService struct {
	db *sql.DB
}

// NewAccountApproverService creates an AccountApproverService.
func NewAccountApproverService(database *sql.DB) (*AccountApproverService, error) {
	if database == nil {
		return nil, errors.New("database connection must not be nil")
	}
	return &AccountApproverService{db: database}, nil
}

// ListBindings returns the approver bindings of one account, enriched with
// user display info and roles.
func (service *AccountApproverService) ListBindings(ctx context.Context, accountID int64) ([]AccountApproverBinding, error) {
	rows, err := service.db.QueryContext(ctx, `SELECT binding.account_id, users.user_id,
			COALESCE(users.display_name, users.user_id), users.email, users.is_active,
			binding.created_at
		FROM aws_account_approver AS binding
		JOIN platform_user AS users ON users.user_id = binding.user_id
		WHERE binding.account_id = $1
		ORDER BY users.display_name, users.user_id`, accountID)
	if err != nil {
		return nil, fmt.Errorf("list account approver bindings: %w", err)
	}
	defer rows.Close()
	bindings := make([]AccountApproverBinding, 0)
	for rows.Next() {
		var binding AccountApproverBinding
		if err := rows.Scan(&binding.AccountID, &binding.UserID, &binding.DisplayName,
			&binding.Email, &binding.IsActive, &binding.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan account approver binding: %w", err)
		}
		binding.Roles = []string{}
		bindings = append(bindings, binding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate account approver bindings: %w", err)
	}
	if err := service.fillRoles(ctx, bindings); err != nil {
		return nil, err
	}
	return bindings, nil
}

// ListCandidates returns every active platform_admin/approval_admin user with
// a Bound flag for the given account, ordered for stable UI rendering.
func (service *AccountApproverService) ListCandidates(ctx context.Context, accountID int64) ([]AccountApproverCandidate, error) {
	rows, err := service.db.QueryContext(ctx, `SELECT users.user_id,
			COALESCE(users.display_name, users.user_id), users.email,
			EXISTS (SELECT 1 FROM aws_account_approver AS binding
				WHERE binding.account_id = $1 AND binding.user_id = users.user_id) AS bound
		FROM platform_user AS users
		JOIN user_role_mapping AS mapping ON mapping.user_id = users.user_id
		JOIN platform_role AS role ON role.id = mapping.role_id
		WHERE users.is_active = TRUE
			AND role.role_code IN ('platform_admin', 'approval_admin')
		GROUP BY users.user_id, users.display_name, users.email
		ORDER BY users.display_name, users.user_id`, accountID)
	if err != nil {
		return nil, fmt.Errorf("list account approver candidates: %w", err)
	}
	defer rows.Close()
	candidates := make([]AccountApproverCandidate, 0)
	for rows.Next() {
		var candidate AccountApproverCandidate
		if err := rows.Scan(&candidate.UserID, &candidate.DisplayName,
			&candidate.Email, &candidate.Bound); err != nil {
			return nil, fmt.Errorf("scan account approver candidate: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate account approver candidates: %w", err)
	}
	return candidates, nil
}

// ListAccountsForApprover returns every account where the user still appears
// in aws_account_approver, regardless of the user's current eligibility.
// The user-management page calls it before deactivating or demoting a user
// (A9③乙) so the operator sees which accounts are about to lose an approver.
func (service *AccountApproverService) ListAccountsForApprover(ctx context.Context, userID string) ([]ApproverAccountSummary, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, errors.New("user id must not be empty")
	}
	rows, err := service.db.QueryContext(ctx, `SELECT binding.account_id,
			account.account_id, account.account_name, binding.created_at
		FROM aws_account_approver AS binding
		JOIN aws_account AS account ON account.id = binding.account_id
		WHERE binding.user_id = $1
		ORDER BY binding.account_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("list approver accounts of user %q: %w", userID, err)
	}
	defer rows.Close()
	summaries := make([]ApproverAccountSummary, 0)
	for rows.Next() {
		var summary ApproverAccountSummary
		if err := rows.Scan(&summary.AccountDBID, &summary.AccountNo,
			&summary.AccountName, &summary.BoundAt); err != nil {
			return nil, fmt.Errorf("scan approver account of user %q: %w", userID, err)
		}
		summaries = append(summaries, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate approver accounts of user %q: %w", userID, err)
	}
	return summaries, nil
}

// SetBindings replaces the whole binding set of one account in a transaction.
// An empty list clears the account's bindings (the caller decides whether an
// account may be left without approvers).
func (service *AccountApproverService) SetBindings(ctx context.Context, accountID int64, userIDs []string) ([]AccountApproverBinding, error) {
	userIDs = normalizeApprovers(userIDs)
	transaction, err := service.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin account approver transaction: %w", err)
	}
	defer transaction.Rollback()

	var exists bool
	if err := transaction.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM aws_account WHERE id = $1)`, accountID,
	).Scan(&exists); err != nil {
		return nil, fmt.Errorf("check AWS account existence: %w", err)
	}
	if !exists {
		return nil, ErrAccountApproverAccountNotFound
	}
	if len(userIDs) > 0 {
		if err := validateApproverUsers(ctx, transaction, userIDs); err != nil {
			return nil, err
		}
	}
	if _, err := transaction.ExecContext(ctx,
		`DELETE FROM aws_account_approver WHERE account_id = $1`, accountID); err != nil {
		return nil, fmt.Errorf("clear account approver bindings: %w", err)
	}
	for _, userID := range userIDs {
		if _, err := transaction.ExecContext(ctx,
			`INSERT INTO aws_account_approver (account_id, user_id) VALUES ($1, $2)
			ON CONFLICT DO NOTHING`, accountID, userID); err != nil {
			return nil, fmt.Errorf("insert account approver binding: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return nil, fmt.Errorf("commit account approver bindings: %w", err)
	}
	return service.ListBindings(ctx, accountID)
}

// SetAccountsForApprover replaces the set of accounts one user approves. It
// is the inverse view of SetBindings — that one answers "who approves this
// account", this one answers "which accounts does this person approve". Both
// write the same aws_account_approver table; keeping only the account-side
// entry forced operators creating a ticket to leave the page, so the user
// editor got its own path.
//
// Only the given user's rows are touched, so other approvers of the same
// accounts keep their bindings. An empty list clears the user's bindings.
func (service *AccountApproverService) SetAccountsForApprover(ctx context.Context, userID string, accountIDs []int64) ([]ApproverAccountSummary, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, errors.New("user id must not be empty")
	}
	accountIDs = normalizeApproverAccountIDs(accountIDs)
	transaction, err := service.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin approver account transaction: %w", err)
	}
	defer transaction.Rollback()

	// The write path must accept exactly the users the read path resolves:
	// binding a standard_user would create tickets nobody can decide.
	if err := validateApproverUsers(ctx, transaction, []string{userID}); err != nil {
		return nil, err
	}
	for _, accountID := range accountIDs {
		var exists bool
		if err := transaction.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM aws_account WHERE id = $1)`, accountID,
		).Scan(&exists); err != nil {
			return nil, fmt.Errorf("check AWS account existence: %w", err)
		}
		if !exists {
			return nil, ErrAccountApproverAccountNotFound
		}
	}
	if _, err := transaction.ExecContext(ctx,
		`DELETE FROM aws_account_approver WHERE user_id = $1`, userID); err != nil {
		return nil, fmt.Errorf("clear approver account bindings: %w", err)
	}
	for _, accountID := range accountIDs {
		if _, err := transaction.ExecContext(ctx,
			`INSERT INTO aws_account_approver (account_id, user_id) VALUES ($1, $2)
			ON CONFLICT DO NOTHING`, accountID, userID); err != nil {
			return nil, fmt.Errorf("insert approver account binding: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return nil, fmt.Errorf("commit approver account bindings: %w", err)
	}
	return service.ListAccountsForApprover(ctx, userID)
}

// normalizeApproverAccountIDs sorts and de-duplicates ids so the emitted
// INSERTs are stable and repeated saves are no-ops.
func normalizeApproverAccountIDs(accountIDs []int64) []int64 {
	if len(accountIDs) == 0 {
		return []int64{}
	}
	seen := make(map[int64]struct{}, len(accountIDs))
	normalized := make([]int64, 0, len(accountIDs))
	for _, accountID := range accountIDs {
		if accountID <= 0 {
			continue
		}
		if _, exists := seen[accountID]; exists {
			continue
		}
		seen[accountID] = struct{}{}
		normalized = append(normalized, accountID)
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i] < normalized[j] })
	return normalized
}

// validateApproverUsers rejects ids that are not active
// platform_admin/approval_admin users, reporting ALL offending ids at once so
// the operator does not have to fix them one by one.
func validateApproverUsers(ctx context.Context, executor interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, userIDs []string) error {
	missing := make([]string, 0)
	for _, userID := range userIDs {
		var ok bool
		if err := executor.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1
			FROM platform_user AS users
			JOIN user_role_mapping AS mapping ON mapping.user_id = users.user_id
			JOIN platform_role AS role ON role.id = mapping.role_id
			WHERE users.user_id = $1 AND users.is_active = TRUE
				AND role.role_code IN ('platform_admin', 'approval_admin'))`, userID,
		).Scan(&ok); err != nil {
			return fmt.Errorf("validate approver user %q: %w", userID, err)
		}
		if !ok {
			missing = append(missing, userID)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("%w: %s", ErrAccountApproverInvalidUser, strings.Join(missing, ", "))
	}
	return nil
}

// fillRoles attaches the role codes of each bound user for display.
func (service *AccountApproverService) fillRoles(ctx context.Context, bindings []AccountApproverBinding) error {
	if len(bindings) == 0 {
		return nil
	}
	for i := range bindings {
		rows, err := service.db.QueryContext(ctx, `SELECT role.role_code
			FROM user_role_mapping AS mapping
			JOIN platform_role AS role ON role.id = mapping.role_id
			WHERE mapping.user_id = $1 ORDER BY role.role_code`, bindings[i].UserID)
		if err != nil {
			return fmt.Errorf("list roles of approver %q: %w", bindings[i].UserID, err)
		}
		roles := make([]string, 0)
		for rows.Next() {
			var code string
			if err := rows.Scan(&code); err != nil {
				rows.Close()
				return fmt.Errorf("scan role of approver %q: %w", bindings[i].UserID, err)
			}
			roles = append(roles, code)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate roles of approver %q: %w", bindings[i].UserID, err)
		}
		bindings[i].Roles = roles
	}
	return nil
}
