// Command diag inspects Redis (asynq queues, heartbeat) and PostgreSQL
// ticket state for local end-to-end debugging.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"
)

func parseEnv(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]string{}
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			out[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return out
}

func main() {
	env := parseEnv(".env")
	redisAddr := env["REDIS_ADDR"]
	if redisAddr == "" {
		redisAddr = "127.0.0.1:6379"
	}
	dbURL := env["DATABASE_URL"]
	clean := len(os.Args) > 1 && os.Args[1] == "-clean"

	// Redis
	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if clean {
		cleanAsynq(ctx, rdb)
		return
	}

	fmt.Println("=== Redis heartbeat ===")
	hb, err := rdb.Get(ctx, "worker:heartbeat:gitstatus").Result()
	if err != nil {
		fmt.Println("heartbeat:", err)
	} else {
		fmt.Println("heartbeat:", hb)
	}

	fmt.Println("\n=== Redis keys (asynq/worker) ===")
	keys, err := rdb.Keys(ctx, "*").Result()
	if err != nil {
		fmt.Println("keys error:", err)
	} else {
		for _, k := range keys {
			if strings.Contains(k, "asynq") || strings.Contains(k, "worker") {
				fmt.Println(k)
			}
		}
	}

	fmt.Println("\n=== asynq:default queue (first 10) ===")
	queueKey := "asynq:default"
	items, err := rdb.LRange(ctx, queueKey, 0, 9).Result()
	if err != nil {
		fmt.Println("lrange error:", err)
	} else {
		fmt.Printf("count in first 10: %d\n", len(items))
		for _, it := range items {
			fmt.Println(truncate(it, 200))
		}
	}
	for _, q := range []string{"asynq:queue:default", "asynq:queue:critical", "asynq:queue:bulk"} {
		n, err := rdb.LLen(ctx, q).Result()
		if err == nil && n > 0 {
			fmt.Printf("%s length=%d\n", q, n)
		}
	}
	// asynq stores pending tasks in sorted sets per queue: asynq:{<qname>}
	zs, err := rdb.Keys(ctx, "asynq:{*}").Result()
	if err == nil {
		for _, z := range zs {
			n, _ := rdb.ZCard(ctx, z).Result()
			fmt.Printf("zset %s card=%d\n", z, n)
		}
	}

	// PostgreSQL
	if dbURL != "" {
		db, err := sql.Open("pgx", dbURL)
		if err != nil {
			fmt.Println("db open error:", err)
			return
		}
		defer db.Close()
		pctx, pcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer pcancel()
		if err := db.PingContext(pctx); err != nil {
			fmt.Println("db ping error:", err)
			return
		}
		fmt.Println("\n=== iam_ticket (latest 15) ===")
		rows, err := db.QueryContext(pctx, `SELECT ticket_no, status, git_provider, git_repository,
			remote_request_number, git_merge_state, git_ci_state, git_apply_result, poll_attempt_count
			FROM iam_ticket ORDER BY created_at DESC LIMIT 15`)
		if err != nil {
			fmt.Println("query error:", err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var ticketNo, status, provider, repo sql.NullString
			var remote, merge, ci, apply sql.NullString
			var attempts int
			if err := rows.Scan(&ticketNo, &status, &provider, &repo, &remote, &merge, &ci, &apply, &attempts); err != nil {
				fmt.Println("scan error:", err)
				continue
			}
			fmt.Printf("%s | status=%s provider=%s repo=%s remote=%s merge=%s ci=%s apply=%s attempts=%d\n",
				nv(ticketNo), nv(status), nv(provider), nv(repo), nv(remote), nv(merge), nv(ci), nv(apply), attempts)
		}

		fmt.Println("\n=== aws_account ===")
		accRows, err := db.QueryContext(pctx, `SELECT id, org_id, account_id, account_name, status
			FROM aws_account ORDER BY id LIMIT 10`)
		if err != nil {
			fmt.Println("aws_account query error:", err)
		} else {
			defer accRows.Close()
			for accRows.Next() {
				var id int64
				var orgID, accountID, accountName, status sql.NullString
				if err := accRows.Scan(&id, &orgID, &accountID, &accountName, &status); err != nil {
					fmt.Println("scan error:", err)
					continue
				}
				fmt.Printf("id=%d org_id=%s account_id=%s name=%s status=%s\n",
					id, nv(orgID), nv(accountID), nv(accountName), nv(status))
			}
		}

		fmt.Println("\n=== platform_user ===")
		usrRows, err := db.QueryContext(pctx, `SELECT user_id, display_name, is_active
			FROM platform_user ORDER BY user_id LIMIT 20`)
		if err != nil {
			fmt.Println("platform_user query error:", err)
		} else {
			defer usrRows.Close()
			for usrRows.Next() {
				var userID, displayName string
				var isActive bool
				if err := usrRows.Scan(&userID, &displayName, &isActive); err != nil {
					fmt.Println("scan error:", err)
					continue
				}
				fmt.Printf("user_id=%s display=%s active=%v\n", userID, displayName, isActive)
			}
		}

		fmt.Println("\n=== ticket_approval ===")
		apprRows, err := db.QueryContext(pctx, `SELECT ta.id, t.ticket_no, ta.approver, ta.approval_result, ta.comment
			FROM ticket_approval ta JOIN iam_ticket t ON t.id = ta.ticket_id
			ORDER BY ta.id LIMIT 20`)
		if err != nil {
			fmt.Println("ticket_approval query error:", err)
		} else {
			defer apprRows.Close()
			for apprRows.Next() {
				var id int64
				var ticketNo, approver, result, comment sql.NullString
				if err := apprRows.Scan(&id, &ticketNo, &approver, &result, &comment); err != nil {
					fmt.Println("scan error:", err)
					continue
				}
				fmt.Printf("id=%d ticket=%s approver=%s result=%s comment=%s\n",
					id, nv(ticketNo), nv(approver), nv(result), nv(comment))
			}
		}

		fmt.Println("\n=== aws_account_config ===")
		cfgRows, err := db.QueryContext(pctx, `SELECT id, aws_account_id, aws_account_db_id, display_name, sync_mode, sync_enabled
			FROM aws_account_config ORDER BY id LIMIT 10`)
		if err != nil {
			fmt.Println("aws_account_config query error:", err)
		} else {
			defer cfgRows.Close()
			for cfgRows.Next() {
				var id int64
				var awsAccountID, displayName, syncMode string
				var awsAccountDBID sql.NullInt64
				var syncEnabled bool
				if err := cfgRows.Scan(&id, &awsAccountID, &awsAccountDBID, &displayName, &syncMode, &syncEnabled); err != nil {
					fmt.Println("scan error:", err)
					continue
				}
				fmt.Printf("id=%d aws_account_id=%s db_id=%d display=%s sync_mode=%s sync_enabled=%v\n",
					id, awsAccountID, awsAccountDBID.Int64, displayName, syncMode, syncEnabled)
			}
		}
	}
}

func nv(v sql.NullString) string {
	if v.Valid {
		return v.String
	}
	return "-"
}

// cleanAsynq removes stale asynq task payloads and pending/retry entries
// for the default queue (test leftovers). Server/worker registrations are preserved.
func cleanAsynq(ctx context.Context, rdb *redis.Client) {
	var deleted int64
	// Delete task payload keys
	for _, pattern := range []string{"asynq:{default}:t:*", "asynq:{default}:dead:*"} {
		keys, err := rdb.Keys(ctx, pattern).Result()
		if err != nil {
			fmt.Println("keys error:", pattern, err)
			continue
		}
		if len(keys) > 0 {
			n, err := rdb.Del(ctx, keys...).Result()
			if err == nil {
				deleted += n
				fmt.Printf("deleted %d keys matching %s\n", n, pattern)
			}
		}
	}
	// Clear pending and retry sorted sets
	for _, zk := range []string{"asynq:{default}", "asynq:{default}:retry", "asynq:{default}:dead"} {
		n, err := rdb.ZCard(ctx, zk).Result()
		if err == nil && n > 0 {
			if _, err := rdb.Del(ctx, zk).Result(); err == nil {
				fmt.Printf("cleared zset %s (%d members)\n", zk, n)
			}
		}
	}
	fmt.Printf("cleanup done, total keys deleted: %d\n", deleted)
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
