package v1

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type AuditRecord struct {
	RequestID    string
	ActorID      string
	Action       string
	ResourceType string
	ResourceID   string
	Outcome      string
	HTTPStatus   int
	Metadata     []byte
	OccurredAt   time.Time
}

type auditWriter interface {
	WriteAuditEvent(context.Context, AuditRecord) error
}

// RequestAuditMiddleware appends request metadata without recording request
// bodies, tokens, cookies, or other sensitive payloads.
func RequestAuditMiddleware(writer auditWriter, logger *slog.Logger) gin.HandlerFunc {
	if logger == nil {
		logger = slog.Default()
	}
	return func(ginContext *gin.Context) {
		requestID := strings.TrimSpace(ginContext.GetHeader("X-Request-ID"))
		if requestID == "" || len(requestID) > 128 {
			generated, err := newRequestID()
			if err != nil {
				logger.Error("generate request ID for audit", "error", err)
				abortError(ginContext, 500, "internal server error")
				return
			}
			requestID = generated
		}
		ginContext.Set("request_id", requestID)
		ginContext.Header("X-Request-ID", requestID)

		ginContext.Next()

		actorID := ""
		if value, exists := ginContext.Get(AuthenticatedUserContextKey); exists {
			if userID, ok := value.(string); ok {
				actorID = strings.TrimSpace(userID)
			}
		}
		route := ginContext.FullPath()
		if route == "" {
			route = "unmatched"
		}
		outcome := "SUCCESS"
		if ginContext.Writer.Status() >= 400 {
			outcome = "FAILURE"
		}
		resourceID := ""
		for _, key := range []string{"ticketNo", "accountId", "organizationId"} {
			if value := ginContext.Param(key); value != "" {
				resourceID = value
				break
			}
		}
		metadata, err := json.Marshal(map[string]string{
			"method": ginContext.Request.Method,
			"route":  route,
		})
		if err != nil {
			logger.Error("encode audit metadata", "request_id", requestID, "error", err)
			return
		}
		event := AuditRecord{
			RequestID:    requestID,
			ActorID:      actorID,
			Action:       ginContext.Request.Method + " " + route,
			ResourceType: routeResourceType(route),
			ResourceID:   resourceID,
			Outcome:      outcome,
			HTTPStatus:   ginContext.Writer.Status(),
			Metadata:     metadata,
			OccurredAt:   time.Now().UTC(),
		}
		auditCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err = writer.WriteAuditEvent(auditCtx, event)
		cancel()
		if err != nil {
			logger.Error("write request audit event", "request_id", requestID, "action", event.Action, "error", err)
		}
	}
}

func routeResourceType(route string) string {
	switch {
	case strings.Contains(route, "tickets"):
		return "iam_ticket"
	case strings.Contains(route, "aws"):
		return "aws_asset"
	default:
		return "http_request"
	}
}

func newRequestID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}
