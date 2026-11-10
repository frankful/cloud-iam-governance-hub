// Command diagpoll directly invokes HandleGitStatusPollTask to surface the
// real error that the asynq worker swallows in its logs.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/hibiken/asynq"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"github.com/frankful/cloud-iam-governance-hub/internal/githost"
	"github.com/frankful/cloud-iam-governance-hub/internal/service"
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
	provider := os.Getenv("PUBLISHER")
	if provider == "" {
		provider = "github"
	}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GIT_TOKEN")
	}
	project := os.Getenv("GITHUB_REPOSITORY")
	if project == "" {
		project = os.Getenv("GIT_PROJECT_ID")
	}

	fmt.Printf("db_url_len=%d redis=%s provider=%s project=%s token_len=%d\n",
		len(dbURL), redisAddr, provider, project, len(token))

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		fmt.Println("open db:", err)
		os.Exit(1)
	}
	defer db.Close()
	if err := db.PingContext(context.Background()); err != nil {
		fmt.Println("ping db:", err)
		os.Exit(1)
	}

	gitHost, err := githost.NewGitHost(githost.GitHostConfig{
		Provider:  provider,
		BaseURL:   envOr("GITHUB_BASE_URL", "https://api.github.com"),
		Token:     token,
		ProjectID: project,
	})
	if err != nil {
		fmt.Println("new git host:", err)
		os.Exit(1)
	}

	gitRepo, err := service.NewSQLGitStatusRepository(db)
	if err != nil {
		fmt.Println("new repo:", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	asynqClient := asynq.NewClient(asynq.RedisClientOpt{Addr: redisAddr})
	defer asynqClient.Close()

	poller, err := service.NewGitStatusPoller(gitHost, gitRepo, asynqClient, logger,
		// 与真实 worker 同语义，便于诊断 CI 门禁关单行为（A12⑤）。
		service.WithCIApplyCallback(
			strings.EqualFold(strings.TrimSpace(os.Getenv("IAM_CI_APPLY_CALLBACK")), "true")))
	if err != nil {
		fmt.Println("new poller:", err)
		os.Exit(1)
	}

	// 目标工单/PR 由环境变量指定，缺省保留历史上的调试目标。
	ticketNo := envOr("DIAG_TICKET_NO", "IAM-0123456789ABCDEF")
	prNumber := envOr("DIAG_PR_NUMBER", "1")
	attempt := 1
	if raw := envOr("DIAG_ATTEMPT", ""); raw != "" {
		if parsed, convErr := strconv.Atoi(raw); convErr == nil && parsed > 0 {
			attempt = parsed
		}
	}
	fmt.Printf("polling ticket=%s pr=%s attempt=%d\n", ticketNo, prNumber, attempt)

	payload, _ := json.Marshal(service.GitStatusPollTask{
		TicketNo:            ticketNo,
		Provider:            "github",
		Project:             project,
		RemoteRequestNumber: prNumber,
		Attempt:             attempt,
	})
	task := asynq.NewTask(service.GitStatusPollTaskType, payload)

	if err := poller.HandleGitStatusPollTask(context.Background(), task); err != nil {
		fmt.Println("HANDLE ERROR:", err)
		os.Exit(1)
	}
	fmt.Println("handler returned nil (success)")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
