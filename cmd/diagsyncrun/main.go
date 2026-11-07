// Temporary diagnostic: dump recent aws_sync_run rows, account sync state,
// and the asynq "sync" queue contents to explain runs stuck in PENDING.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		fmt.Println("load .env:", err)
	}
	dbURL := os.Getenv("DATABASE_URL")
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "127.0.0.1:6379"
	}

	// Redis: asynq sync queue state
	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fmt.Println("=== redis asynq keys ===")
	keys, err := rdb.Keys(ctx, "asynq:*sync*").Result()
	if err != nil {
		fmt.Println("keys error:", err)
	}
	for _, k := range keys {
		t, _ := rdb.Type(ctx, k).Result()
		n, _ := rdb.ZCard(ctx, k).Result()
		ll, _ := rdb.LLen(ctx, k).Result()
		fmt.Printf("%s type=%s zcard=%d llen=%d\n", k, t, n, ll)
		if t == "zset" && n > 0 {
			items, _ := rdb.ZRange(ctx, k, 0, 4).Result()
			for _, it := range items {
				fmt.Printf("    %s\n", strings.ReplaceAll(it, "\n", " ")[:min(400, len(it))])
			}
		}
	}
	hb, err := rdb.Get(ctx, "worker:heartbeat:sync").Result()
	fmt.Println("worker:heartbeat:sync =", hb, err)

	if dbURL == "" {
		fmt.Println("DATABASE_URL not set")
		return
	}
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		fmt.Println("db open:", err)
		return
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		fmt.Println("db ping:", err)
		return
	}

	fmt.Println("\n=== aws_sync_run (latest 15) ===")
	rows, err := db.QueryContext(ctx, `SELECT id, aws_account_config_id, aws_account_id,
		trigger_source, triggered_by, status, started_at, finished_at, last_error,
		created_at FROM aws_sync_run ORDER BY created_at DESC LIMIT 15`)
	if err != nil {
		fmt.Println("query:", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id, cfgID int64
		var acct, trig, actor, status string
		var started, finished, lastErr sql.NullString
		var created time.Time
		if err := rows.Scan(&id, &cfgID, &acct, &trig, &actor, &status, &started, &finished, &lastErr, &created); err != nil {
			fmt.Println("scan:", err)
			continue
		}
		fmt.Printf("id=%d cfg=%d acct=%s trig=%s by=%s status=%s started=%s finished=%s created=%s err=%s\n",
			id, cfgID, acct, trig, actor, status, nv(started), nv(finished),
			created.Format("2006-01-02 15:04:05"), nv(lastErr))
	}

	if len(os.Args) > 1 && os.Args[1] == "-tickets" {
		fmt.Println("\n=== eks-upgrade-backup-role-policy related tickets ===")
		tRows, err := db.QueryContext(ctx, `SELECT COALESCE(ticket_no,'-'), COALESCE(ticket_type,'-'),
			COALESCE(principal_name,'-'), COALESCE(status,'-'),
			request_policy->>'source_ticket_no' AS src,
			created_at::text,
			(terraform_code LIKE '%aws_iam_role_policy" "managed_policy"') AS has_managed,
			(terraform_code LIKE '%aws_iam_role_policy" "inline_policy"') AS has_inline
			FROM iam_ticket
			WHERE terraform_code LIKE '%eks-upgrade-backup-role-policy%'
			ORDER BY created_at`)
		if err != nil {
			fmt.Println("query:", err)
			return
		}
		defer tRows.Close()
		for tRows.Next() {
			var tno, ttype, pname, status, created string
			var src sql.NullString
			var hasManaged, hasInline bool
			if err := tRows.Scan(&tno, &ttype, &pname, &status, &src, &created, &hasManaged, &hasInline); err != nil {
				fmt.Println("scan:", err)
				continue
			}
			fmt.Printf("%s type=%s principal=%s status=%s src=%s created=%s managed_policy=%v inline_policy=%v\n",
				tno, ttype, pname, status, nv(src), created, hasManaged, hasInline)
		}
		fmt.Println("\n=== ticket IAM-560D7A581A27F9E8 ===")
		row := db.QueryRowContext(ctx, `SELECT COALESCE(ticket_no,'-'), COALESCE(ticket_type,'-'),
			COALESCE(principal_name,'-'), COALESCE(status,'-'),
			COALESCE(closure_reason,'-'),
			request_policy->>'source_ticket_no', created_at::text
			FROM iam_ticket WHERE lower(ticket_no) = 'iam-560d7a581a27f9e8'`)
		var tno, ttype, pname, status, closure, created string
		var src sql.NullString
		if err := row.Scan(&tno, &ttype, &pname, &status, &closure, &src, &created); err != nil {
			fmt.Println("query:", err)
		} else {
			fmt.Printf("%s type=%s principal=%s status=%s closure=%s src=%s created=%s\n", tno, ttype, pname, status, closure, nv(src), created)
		}
		return
	}

	fmt.Println("\n=== aws_account_config sync state ===")
	cfgRows, err := db.QueryContext(ctx, `SELECT id, aws_account_id, display_name,
		sync_enabled, sync_status, last_sync_attempt_at, last_successful_sync_at, last_sync_error
		FROM aws_account_config ORDER BY id`)
	if err != nil {
		fmt.Println("query:", err)
		return
	}
	defer cfgRows.Close()
	for cfgRows.Next() {
		var id int64
		var acct, display, syncStatus string
		var enabled bool
		var attempt, success sql.NullString
		var syncErr sql.NullString
		if err := cfgRows.Scan(&id, &acct, &display, &enabled, &syncStatus, &attempt, &success, &syncErr); err != nil {
			fmt.Println("scan:", err)
			continue
		}
		fmt.Printf("id=%d acct=%s display=%s enabled=%v status=%s attempt=%s success=%s err=%s\n",
			id, acct, display, enabled, syncStatus, nv(attempt), nv(success), nv(syncErr))
	}
}

func nv(v sql.NullString) string {
	if v.Valid {
		return v.String
	}
	return "-"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
