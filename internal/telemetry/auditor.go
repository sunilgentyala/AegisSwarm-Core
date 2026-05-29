// Package telemetry provides OpenTelemetry tracing and cryptographically
// signed audit logging for the AegisSwarm framework.
package telemetry

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.uber.org/zap"
)

// AuditRecord is the structured, tamper-evident log entry for every tool call.
type AuditRecord struct {
	Timestamp   string          `json:"timestamp"`
	AgentID     string          `json:"agent_id"`
	SessionID   string          `json:"session_id"`
	ToolID      string          `json:"tool_id"`
	Decision    string          `json:"decision"` // "allow", "deny", "escalate"
	RiskScore   float64         `json:"risk_score"`
	Payload     json.RawMessage `json:"payload_hash"` // SHA-256 of the original payload
	HMAC        string          `json:"hmac"`
}

// Auditor writes HMAC-signed audit records to a structured log and
// publishes OpenTelemetry spans for every tool invocation.
type Auditor struct {
	logger    *zap.Logger
	hmacKey   []byte
}

// NewAuditor constructs an Auditor using the AEGIS_AUDIT_KEY env variable
// as the HMAC secret. In production, source this from a KMS-backed secret store.
func NewAuditor() *Auditor {
	key := []byte(os.Getenv("AEGIS_AUDIT_KEY"))
	if len(key) == 0 {
		key = []byte("changeme-replace-with-kms-secret")
	}
	logger, _ := zap.NewProduction()
	return &Auditor{logger: logger, hmacKey: key}
}

// WriteRecord signs and persists an audit record.
func (a *Auditor) WriteRecord(agentID, sessionID, toolID, decision string, riskScore float64, rawPayload []byte) {
	payloadHash := sha256.Sum256(rawPayload)
	hashHex := hex.EncodeToString(payloadHash[:])

	record := AuditRecord{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		AgentID:   agentID,
		SessionID: sessionID,
		ToolID:    toolID,
		Decision:  decision,
		RiskScore: riskScore,
		Payload:   json.RawMessage(fmt.Sprintf("%q", hashHex)),
	}

	recordJSON, err := json.Marshal(record)
	if err != nil {
		a.logger.Error("audit record marshal failed", zap.Error(err))
		return
	}

	mac := hmac.New(sha256.New, a.hmacKey)
	mac.Write(recordJSON)
	record.HMAC = hex.EncodeToString(mac.Sum(nil))

	a.logger.Info("audit",
		zap.String("agent_id", agentID),
		zap.String("session_id", sessionID),
		zap.String("tool_id", toolID),
		zap.String("decision", decision),
		zap.Float64("risk_score", riskScore),
		zap.String("payload_sha256", hashHex),
		zap.String("hmac", record.HMAC),
	)
}

// InitTracerProvider initialises an OTLP gRPC tracer provider.
func InitTracerProvider(ctx context.Context, otlpEndpoint, serviceName string) (*sdktrace.TracerProvider, error) {
	exp, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(otlpEndpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("OTLP exporter init failed: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName(serviceName)),
		resource.WithAttributes(semconv.ServiceVersion("1.0.0")),
	)
	if err != nil {
		return nil, fmt.Errorf("OTel resource build failed: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)
	return tp, nil
}
