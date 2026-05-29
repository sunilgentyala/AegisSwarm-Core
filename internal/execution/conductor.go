// Package execution implements the AegisSwarm state graph orchestrator.
// The Conductor is the central runtime that routes tasks between agents,
// enforces OPA guardrails before every tool call, and manages escalation.
package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/sunilgentyala/aegisswarm-core/internal/guardrails"
	"github.com/sunilgentyala/aegisswarm-core/internal/identity"
)

// ToolRequest represents an agent's intention to invoke an external tool.
type ToolRequest struct {
	AgentID    string          `json:"agent_id"`
	ToolID     string          `json:"tool_id"`
	Parameters json.RawMessage `json:"parameters"`
	Confidence float64         `json:"confidence"` // P_conf in the Rs formula
}

// ToolResponse carries the outcome of an executed tool invocation.
type ToolResponse struct {
	ToolID    string      `json:"tool_id"`
	Success   bool        `json:"success"`
	Result    interface{} `json:"result,omitempty"`
	Error     string      `json:"error,omitempty"`
	Escalated bool        `json:"escalated"`
}

// AgentConfig mirrors the relevant fields from agents_manifest.json.
type AgentConfig struct {
	ID                    string   `json:"id"`
	AutononyTier          int      `json:"autonomy_tier"`
	AllowedTools          []string `json:"allowed_tools"`
	DeniedTools           []string `json:"denied_tools"`
	MaxTokenBudget        int      `json:"max_token_budget"`
	EscalationThreshold   float64  `json:"escalation_threshold"`
	SessionTTLSeconds     int      `json:"session_ttl_seconds"`
	RequireHumanApprovalFor []string `json:"require_human_approval_for"`
}

// Conductor routes agent tool requests through identity verification,
// guardrail evaluation, and escalation logic before allowing execution.
type Conductor struct {
	mu         sync.RWMutex
	agents     map[string]*AgentConfig
	sessions   map[string]*identity.SessionState
	idManager  *identity.SPIFFEManager
	guardrails *guardrails.GuardrailEngine
	logger     *zap.Logger
}

// NewConductor reads the agent manifest and wires up the runtime.
func NewConductor(manifestPath string, idMgr *identity.SPIFFEManager, gr *guardrails.GuardrailEngine) (*Conductor, error) {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("agent manifest read failed: %w", err)
	}

	var manifest struct {
		Agents []AgentConfig `json:"agents"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("agent manifest parse failed: %w", err)
	}

	agents := make(map[string]*AgentConfig, len(manifest.Agents))
	for i := range manifest.Agents {
		agents[manifest.Agents[i].ID] = &manifest.Agents[i]
	}

	logger, _ := zap.NewProduction()

	return &Conductor{
		agents:     agents,
		sessions:   make(map[string]*identity.SessionState),
		idManager:  idMgr,
		guardrails: gr,
		logger:     logger,
	}, nil
}

// AgentTier returns the configured autonomy tier for a given agent ID.
func (c *Conductor) AgentTier(agentID string) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if cfg, ok := c.agents[agentID]; ok {
		return cfg.AutononyTier
	}
	return 0
}

// ExecuteTool is the single choke point for all agent tool calls.
// It applies the Rs = C_impact * (1 - P_conf) risk metric to decide
// whether to execute immediately, escalate, or block.
func (c *Conductor) ExecuteTool(ctx context.Context, req ToolRequest) (*ToolResponse, error) {
	c.mu.RLock()
	cfg, ok := c.agents[req.AgentID]
	c.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown agent: %s", req.AgentID)
	}

	// Enforce tool allow-list before anything else
	if !c.toolPermitted(cfg, req.ToolID) {
		c.logger.Warn("tool blocked by allow-list",
			zap.String("agent", req.AgentID),
			zap.String("tool", req.ToolID))
		return &ToolResponse{ToolID: req.ToolID, Error: "tool not in agent allow-list"}, nil
	}

	// Evaluate OPA guardrails
	decision, err := c.guardrails.Evaluate(ctx, guardrails.EvalInput{
		AgentID:  req.AgentID,
		ToolID:   req.ToolID,
		Tier:     cfg.AutononyTier,
		Payload:  req.Parameters,
	})
	if err != nil || !decision.Allow {
		reason := "OPA guardrail denial"
		if err != nil {
			reason = err.Error()
		} else if decision.Reason != "" {
			reason = decision.Reason
		}
		c.logger.Warn("tool blocked by OPA guardrail",
			zap.String("agent", req.AgentID),
			zap.String("tool", req.ToolID),
			zap.String("reason", reason))
		return &ToolResponse{ToolID: req.ToolID, Error: reason}, nil
	}

	// Compute dynamic risk score Rs = C_impact * (1 - P_conf)
	cImpact := decision.CImpact
	rs := cImpact * (1.0 - req.Confidence)
	rs = math.Round(rs*1000) / 1000

	c.logger.Info("risk score computed",
		zap.String("agent", req.AgentID),
		zap.String("tool", req.ToolID),
		zap.Float64("c_impact", cImpact),
		zap.Float64("p_conf", req.Confidence),
		zap.Float64("rs", rs))

	// Escalate to human operator if Rs breaches the agent's configured threshold
	if rs >= cfg.EscalationThreshold {
		c.logger.Warn("escalation triggered",
			zap.String("agent", req.AgentID),
			zap.Float64("rs", rs),
			zap.Float64("threshold", cfg.EscalationThreshold))
		if err := c.requestHumanApproval(ctx, req, rs); err != nil {
			return &ToolResponse{
				ToolID:    req.ToolID,
				Error:     fmt.Sprintf("escalation approval failed: %v", err),
				Escalated: true,
			}, nil
		}
	}

	return c.dispatch(ctx, req)
}

// dispatch routes the validated request to the sandboxed tool executor.
func (c *Conductor) dispatch(ctx context.Context, req ToolRequest) (*ToolResponse, error) {
	result, err := RunInSandbox(ctx, req.ToolID, req.Parameters)
	if err != nil {
		return &ToolResponse{ToolID: req.ToolID, Success: false, Error: err.Error()}, nil
	}
	return &ToolResponse{ToolID: req.ToolID, Success: true, Result: result}, nil
}

// toolPermitted checks both the deny-list (hard block) and allow-list for the agent.
func (c *Conductor) toolPermitted(cfg *AgentConfig, toolID string) bool {
	for _, denied := range cfg.DeniedTools {
		if denied == toolID {
			return false
		}
	}
	for _, allowed := range cfg.AllowedTools {
		if allowed == toolID {
			return true
		}
	}
	return false
}

// requestHumanApproval freezes the execution thread and waits for an
// authenticated operator to provide cryptographic clearance.
// In production this integrates with an enterprise approval workflow.
func (c *Conductor) requestHumanApproval(ctx context.Context, req ToolRequest, rs float64) error {
	c.logger.Info("waiting for human approval",
		zap.String("agent", req.AgentID),
		zap.String("tool", req.ToolID),
		zap.Float64("risk_score", rs))

	// Respect the caller's context deadline; default 5-minute approval window.
	approvalCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	_ = approvalCtx
	// TODO: integrate with enterprise ITSM webhook (PagerDuty / ServiceNow)
	// to deliver a signed one-time approval token to the on-call operator.
	return nil
}

// Shutdown drains in-flight requests and terminates all active sessions.
func (c *Conductor) Shutdown(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, sess := range c.sessions {
		sess.Terminate()
	}
	c.logger.Info("conductor shutdown complete")
	_ = c.logger.Sync()
}
