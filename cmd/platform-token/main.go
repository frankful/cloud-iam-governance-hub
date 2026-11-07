package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
)

func main() {
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(os.Stderr, "load .env:", err)
		os.Exit(1)
	}
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "platform-token:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr *os.File) error {
	flags := flag.NewFlagSet("platform-token", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databaseURL := flags.String("database-url", strings.TrimSpace(os.Getenv("DATABASE_URL")), "PostgreSQL URL (defaults to DATABASE_URL)")
	userID := flags.String("user-id", "", "existing active platform user ID")
	name := flags.String("name", "", "human-readable token name")
	expiry := flags.Duration("expires-in", 30*24*time.Hour, "token validity duration")
	bootstrapAdmin := flags.Bool("bootstrap-admin", false,
		"first-use bootstrap: grant platform_admin to the user when it has no role yet")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if strings.TrimSpace(*databaseURL) == "" {
		return errors.New("database URL is required via -database-url or DATABASE_URL")
	}
	if *expiry <= 0 {
		return errors.New("-expires-in must be positive")
	}

	database, err := sql.Open("pgx", *databaseURL)
	if err != nil {
		return fmt.Errorf("open PostgreSQL connection: %w", err)
	}
	defer database.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := database.PingContext(ctx); err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}

	repository, err := service.NewSQLPlatformTokenRepository(database)
	if err != nil {
		return err
	}
	tokenService, err := service.NewPlatformTokenService(repository)
	if err != nil {
		return err
	}

	// 首用自举：全新安装没有任何 token，HTTP 签发接口又要求已登录的管理员，
	// 只能靠本 CLI 直连数据库签发第一枚。无角色用户签发的 token 无法登录
	// （Authenticate 要求 len(roles)>0），--bootstrap-admin 顺带把首个
	// platform_admin 角色授出去，让「第一次登录」真正闭环。
	if *bootstrapAdmin {
		granted, err := grantPlatformAdmin(ctx, database, *userID)
		if err != nil {
			return err
		}
		if granted {
			fmt.Fprintf(stderr, "granted platform_admin to %q (bootstrap)\n", *userID)
		}
	}

	expiresAt := time.Now().UTC().Add(*expiry)
	// CLI 发给自己：操作者与令牌归属同一人。
	issued, err := tokenService.IssueToken(ctx, *userID, *userID, *name, &expiresAt)
	if errors.Is(err, service.ErrPlatformUserNoRole) {
		return fmt.Errorf("user %q has no platform role; rerun with -bootstrap-admin to grant platform_admin", *userID)
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(issued); err != nil {
		return fmt.Errorf("write one-time token response: %w", err)
	}
	return nil
}

// grantPlatformAdmin inserts the platform_admin role mapping for userID when
// the user has no role yet. Returns whether a grant happened.
func grantPlatformAdmin(ctx context.Context, database *sql.DB, userID string) (bool, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return false, errors.New("-user-id is required")
	}
	var roles int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*)
		FROM user_role_mapping m
		JOIN platform_user u ON u.user_id = m.user_id AND u.is_active = TRUE
		WHERE m.user_id = $1`, userID).Scan(&roles); err != nil {
		return false, fmt.Errorf("count platform user roles: %w", err)
	}
	if roles > 0 {
		return false, nil
	}
	result, err := database.ExecContext(ctx, `INSERT INTO user_role_mapping (user_id, role_id)
		SELECT $1, r.id FROM platform_role r
		WHERE r.role_code = 'platform_admin'
		ON CONFLICT DO NOTHING`, userID)
	if err != nil {
		return false, fmt.Errorf("grant platform_admin: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read grant result: %w", err)
	}
	return affected > 0, nil
}
