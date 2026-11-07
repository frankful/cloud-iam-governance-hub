package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

func main() {
	data, _ := os.ReadFile(".env")
	redisAddr := "127.0.0.1:6379"
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "REDIS_ADDR=") {
			redisAddr = strings.TrimPrefix(line, "REDIS_ADDR=")
		}
	}
	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, k := range []string{"asynq:{default}:processed", "asynq:{default}:failed", "asynq:{default}:processed:2026-10-09", "asynq:{default}:failed:2026-10-09"} {
		v, _ := rdb.Get(ctx, k).Result()
		fmt.Printf("%s = %s\n", k, v)
	}
	// check for retry/scheduled/pending leftovers
	for _, pattern := range []string{"asynq:{default}:pending", "asynq:{default}:scheduled", "asynq:{default}:retry", "asynq:{default}:archived", "asynq:{default}:active"} {
		t, _ := rdb.Type(ctx, pattern).Result()
		if t == "zset" {
			n, _ := rdb.ZCard(ctx, pattern).Result()
			fmt.Printf("ZSET %s = %d\n", pattern, n)
			if n > 0 {
				items, _ := rdb.ZRange(ctx, pattern, 0, 3).Result()
				for _, it := range items {
					fmt.Printf("    %.500s\n", it)
				}
			}
		} else if t == "list" {
			n, _ := rdb.LLen(ctx, pattern).Result()
			fmt.Printf("LIST %s = %d\n", pattern, n)
		}
	}
}
