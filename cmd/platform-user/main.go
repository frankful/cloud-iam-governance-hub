// Command platform-user upserts a platform_user row: the identity a person
// signs in with. It is the onboarding step for every platform user, not a
// development-only helper — API writes that carry actor attribution
// (aws_account_config.created_by, iam_ticket.approver_ids) enforce a
// platform_user foreign key, and development auth (X-User-ID) does not
// provision users, so users are seeded explicitly.
//
// The command is idempotent: re-running it updates the display name and role
// of an existing user.
//
// Usage:
//
//	platform-user <user_id> [display_name] [role]
//
// role is one of platform_admin, approval_admin, standard_user (default
// platform_admin). After creating the user, issue a login token with
// cmd/platform-token.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: platform-user <user_id> [display_name] [role]")
		os.Exit(2)
	}
	userID := strings.TrimSpace(os.Args[1])
	displayName := userID
	if len(os.Args) > 2 {
		displayName = strings.TrimSpace(os.Args[2])
	}
	role := "platform_admin"
	if len(os.Args) > 3 {
		role = strings.TrimSpace(os.Args[3])
	}
	if userID == "" {
		fmt.Fprintln(os.Stderr, "user_id must not be empty")
		os.Exit(2)
	}
	if role != "platform_admin" && role != "approval_admin" && role != "standard_user" {
		fmt.Fprintln(os.Stderr, "role must be platform_admin, approval_admin or standard_user")
		os.Exit(2)
	}
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(os.Stderr, "load .env:", err)
		os.Exit(1)
	}
	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if databaseURL == "" {
		databaseURL = "postgres://finops:finops@127.0.0.1:5432/finops?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open database:", err)
		os.Exit(1)
	}
	defer database.Close()
	_, err = database.ExecContext(ctx, `INSERT INTO platform_user (user_id, display_name, is_active)
		VALUES ($1, $2, TRUE)
		ON CONFLICT (user_id) DO UPDATE SET display_name = EXCLUDED.display_name, updated_at = NOW()`,
		userID, displayName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upsert platform_user:", err)
		os.Exit(1)
	}
	// 角色映射按「设置」语义处理：先清掉该用户已有的角色，再挂上本次指定的
	// 角色（ON CONFLICT DO NOTHING 会让旧角色赖着不走，管理员改不了人的权限）。
	if _, err = database.ExecContext(ctx,
		`DELETE FROM user_role_mapping WHERE user_id = $1`, userID); err != nil {
		fmt.Fprintln(os.Stderr, "clear platform roles:", err)
		os.Exit(1)
	}
	if _, err = database.ExecContext(ctx, `INSERT INTO user_role_mapping (user_id, role_id, assigned_by)
		SELECT $1, role.id, $1 FROM platform_role AS role WHERE role.role_code = $2
		ON CONFLICT (user_id, role_id) DO NOTHING`, userID, role); err != nil {
		fmt.Fprintln(os.Stderr, "assign platform role:", err)
		os.Exit(1)
	}
	fmt.Printf("platform_user %q ready with role %s\n", userID, role)
}
