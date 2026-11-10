// Command enqueue-poll manually enqueues a gitstatus:poll task for testing
// the end-to-end publish → poll → auto-close flow.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hibiken/asynq"
)

type pollTask struct {
	TicketNo            string `json:"ticket_no"`
	Provider            string `json:"provider"`
	Project             string `json:"project"`
	RemoteRequestNumber string `json:"remote_request_number"`
	CommitSHA           string `json:"commit_sha,omitempty"`
	Attempt             int    `json:"attempt"`
}

func main() {
	ticketNo := "IAM-0123456789ABCDEF"
	project := "example-org/iam-baseline"
	prNumber := "1"
	delay := 0 * time.Second
	for i, arg := range os.Args[1:] {
		switch arg {
		case "-ticket":
			ticketNo = os.Args[i+2]
		case "-project":
			project = os.Args[i+2]
		case "-pr":
			prNumber = os.Args[i+2]
		case "-delay":
			if d, err := time.ParseDuration(os.Args[i+2]); err == nil {
				delay = d
			}
		}
	}

	redisAddr := "127.0.0.1:6379"
	if data, err := os.ReadFile(".env"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimRight(strings.TrimSpace(line), "\r")
			if strings.HasPrefix(line, "REDIS_ADDR=") {
				redisAddr = strings.TrimPrefix(line, "REDIS_ADDR=")
			}
		}
	}

	payload, err := json.Marshal(pollTask{
		TicketNo:            ticketNo,
		Provider:            "github",
		Project:             project,
		RemoteRequestNumber: prNumber,
		Attempt:             1,
	})
	if err != nil {
		fmt.Println("marshal error:", err)
		os.Exit(1)
	}

	client := asynq.NewClient(asynq.RedisClientOpt{Addr: redisAddr})
	defer client.Close()

	task := asynq.NewTask("gitstatus:poll", payload)
	var info *asynq.TaskInfo
	if delay > 0 {
		info, err = client.EnqueueContext(context.Background(), task, asynq.ProcessIn(delay), asynq.Queue("gitstatus"))
	} else {
		info, err = client.EnqueueContext(context.Background(), task, asynq.Queue("gitstatus"))
	}
	if err != nil {
		fmt.Println("enqueue error:", err)
		os.Exit(1)
	}
	fmt.Printf("enqueued task id=%s queue=%s state=%s\n", info.ID, info.Queue, info.State)
}
