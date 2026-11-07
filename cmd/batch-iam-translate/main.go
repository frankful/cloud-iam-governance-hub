package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	awsadapter "github.com/frankful/cloud-iam-governance-hub/pkg/adapter/aws"
	"github.com/frankful/cloud-iam-governance-hub/pkg/model/abstractiam"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
)

type translationResult struct {
	PolicyID     int64                       `json:"policy_id"`
	PolicyARN    *string                     `json:"policy_arn,omitempty"`
	PolicyName   *string                     `json:"policy_name,omitempty"`
	PolicyType   *string                     `json:"policy_type,omitempty"`
	Abstract     *abstractiam.AbstractPolicy `json:"abstract_policy,omitempty"`
	ParseStatus  string                      `json:"parse_status"`
	ParseMessage string                      `json:"parse_msg,omitempty"`
}

func main() {
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("load .env: %v", err)
	}
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "batch-iam-translate:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("batch-iam-translate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databaseURL := flags.String("database-url", strings.TrimSpace(os.Getenv("DATABASE_URL")), "PostgreSQL connection URL (defaults to DATABASE_URL)")
	outputPath := flags.String("output", "-", "output JSON file path, or - for stdout")
	accountID := flags.Int64("account-db-id", 0, "limit policies to principals/groups in this aws_account.id")
	timeout := flags.Duration("timeout", 2*time.Minute, "database query timeout")
	limit := flags.Int("limit", 0, "maximum policies to translate (0 means no limit)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	if strings.TrimSpace(*databaseURL) == "" {
		return errors.New("database URL is required via -database-url or DATABASE_URL")
	}
	if *accountID < 0 || *limit < 0 || *timeout <= 0 {
		return errors.New("account database ID and limit must be non-negative and timeout must be positive")
	}

	database, err := sql.Open("pgx", *databaseURL)
	if err != nil {
		return fmt.Errorf("open PostgreSQL connection: %w", err)
	}
	defer database.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := database.PingContext(ctx); err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	results, err := translatePolicies(ctx, database, *accountID, *limit)
	if err != nil {
		return err
	}

	var destination io.Writer = stdout
	var outputFile *os.File
	if *outputPath != "-" {
		outputFile, err = os.OpenFile(*outputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer outputFile.Close()
		destination = outputFile
	}
	encoder := json.NewEncoder(destination)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		return fmt.Errorf("write translation output: %w", err)
	}
	failed, partial := 0, 0
	for _, result := range results {
		switch result.ParseStatus {
		case awsadapter.ParseStatusFailed:
			failed++
		case awsadapter.ParseStatusPartial:
			partial++
		}
	}
	_, _ = fmt.Fprintf(stderr, "translated=%d partial=%d failed=%d output=%s\n",
		len(results), partial, failed, *outputPath)
	return nil
}

func translatePolicies(
	ctx context.Context,
	database *sql.DB,
	accountID int64,
	limit int,
) ([]translationResult, error) {
	query := `SELECT policy.id, policy.policy_arn, policy.policy_name,
		policy.policy_type, policy.policy_document
		FROM iam_policy AS policy
		WHERE policy.policy_document IS NOT NULL`
	args := make([]interface{}, 0, 2)
	if accountID > 0 {
		query += ` AND (EXISTS (
			SELECT 1
			FROM iam_principal_policy AS association
			JOIN iam_principal AS principal ON principal.id = association.principal_id
			WHERE association.policy_id = policy.id
				AND principal.account_id = $1 AND principal.is_deleted = FALSE
		) OR EXISTS (
			SELECT 1
			FROM iam_group_policy AS group_association
			JOIN iam_group AS iam_group ON iam_group.id = group_association.group_id
			WHERE group_association.policy_id = policy.id AND iam_group.account_id = $1
		))`
		args = append(args, accountID)
	}
	query += ` ORDER BY policy.id`
	if limit > 0 {
		args = append(args, limit)
		query += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	rows, err := database.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query IAM policies: %w", err)
	}
	defer rows.Close()

	translator := &awsadapter.AwsAdapter{}
	results := make([]translationResult, 0)
	for rows.Next() {
		var result translationResult
		var policyJSON []byte
		if err := rows.Scan(
			&result.PolicyID,
			&result.PolicyARN,
			&result.PolicyName,
			&result.PolicyType,
			&policyJSON,
		); err != nil {
			return nil, fmt.Errorf("scan IAM policy: %w", err)
		}
		abstract, status, message, parseErr := translator.FromCloudPolicy(json.RawMessage(policyJSON))
		result.Abstract = abstract
		result.ParseStatus = status
		result.ParseMessage = message
		if parseErr != nil && status != awsadapter.ParseStatusFailed {
			return nil, fmt.Errorf("translate IAM policy %d: %w", result.PolicyID, parseErr)
		}
		results = append(results, result)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate IAM policies: %w", err)
	}
	return results, nil
}
