// Package guardrails implements dual-stage prompt-injection detection
// and semantic goal verification for the AegisSwarm framework.
package guardrails

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/open-policy-agent/opa/rego"
	"go.uber.org/zap"
)

// EvalInput is the structured payload passed to OPA for every tool request.
type EvalInput struct {
	AgentID string          `json:"agent_id"`
	ToolID  string          `json:"tool_id"`
	Tier    int             `json:"tier"`
	Payload json.RawMessage `json:"payload"`
}

// EvalDecision is the structured output returned by OPA guardrail evaluation.
type EvalDecision struct {
	Allow   bool    `json:"allow"`
	Reason  string  `json:"reason"`
	CImpact float64 `json:"c_impact"`
}

// GuardrailEngine holds compiled OPA policies and injection-detection patterns.
type GuardrailEngine struct {
	query      rego.PreparedEvalQuery
	scopeIndex map[string]toolScope
	patterns   []*regexp.Regexp
	logger     *zap.Logger
}

type toolScope struct {
	ToolID  string  `json:"tool_id"`
	Blocked bool    `json:"blocked"`
	CImpact float64 `json:"c_impact"`
}

// injectionPatterns detects known indirect prompt-injection payloads.
// Patterns target override instructions, role-swap commands, and
// out-of-band instruction injection common in supplier documents.
var injectionPatterns = []string{
	`(?i)ignore\s+(previous|all|above)\s+(instructions?|prompts?)`,
	`(?i)override\s+system\s+(instructions?|prompt)`,
	`(?i)you\s+are\s+now\s+(a\s+)?(?:different|evil|unrestricted|DAN)`,
	`(?i)transfer\s+all\s+(available|remaining)\s+(funds?|reserves?|balance)`,
	`(?i)disregard\s+your\s+(training|guidelines|instructions?)`,
	`(?i)act\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:a\s+)?(?:DAN|evil|jailbreak)`,
	`(?i)do\s+not\s+(?:follow|adhere\s+to)\s+(?:your\s+)?(?:safety|security)\s+(?:rules?|guidelines?)`,
	`(?i)execute\s+(?:the\s+following\s+)?(?:system\s+)?command`,
}

// NewGuardrailEngine compiles OPA policies from policyDir and builds
// the tool scope index from the scopes JSON file.
func NewGuardrailEngine(policyDir, scopePath string) (*GuardrailEngine, error) {
	logger, _ := zap.NewProduction()

	// Load all .rego files from the policy directory
	regoFiles, err := filepath.Glob(filepath.Join(policyDir, "*.rego"))
	if err != nil || len(regoFiles) == 0 {
		return nil, fmt.Errorf("no .rego files found in %s: %w", policyDir, err)
	}

	modules := make([]func(*rego.Rego), 0, len(regoFiles)+1)
	for _, f := range regoFiles {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("rego file read failed (%s): %w", f, err)
		}
		name := filepath.Base(f)
		src := string(raw)
		modules = append(modules, rego.Module(name, src))
	}
	modules = append(modules, rego.Query("data.aegisswarm.guardrail.decision"))

	query, err := rego.New(modules...).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("OPA policy compilation failed: %w", err)
	}

	// Parse tool scopes for the C_impact lookup table
	scopeIndex, err := loadScopeIndex(scopePath)
	if err != nil {
		return nil, fmt.Errorf("tool scope load failed: %w", err)
	}

	// Compile injection detection patterns
	compiled := make([]*regexp.Regexp, 0, len(injectionPatterns))
	for _, pat := range injectionPatterns {
		compiled = append(compiled, regexp.MustCompile(pat))
	}

	return &GuardrailEngine{
		query:      query,
		scopeIndex: scopeIndex,
		patterns:   compiled,
		logger:     logger,
	}, nil
}

// Evaluate runs dual-stage guardrail checks:
//  1. Regex-based prompt injection screening of the payload
//  2. OPA policy evaluation for structural access control
func (g *GuardrailEngine) Evaluate(ctx context.Context, input EvalInput) (*EvalDecision, error) {
	// Stage 1: injection screen
	rawPayload := string(input.Payload)
	if hit, pattern := g.detectInjection(rawPayload); hit {
		g.logger.Warn("prompt injection detected",
			zap.String("agent", input.AgentID),
			zap.String("pattern", pattern))
		return &EvalDecision{Allow: false, Reason: fmt.Sprintf("injection pattern matched: %s", pattern)}, nil
	}

	// Resolve C_impact from scope index
	scope, ok := g.scopeIndex[input.ToolID]
	if !ok {
		return &EvalDecision{Allow: false, Reason: "unknown tool: no scope defined"}, nil
	}
	if scope.Blocked {
		return &EvalDecision{Allow: false, Reason: "tool is globally blocked"}, nil
	}

	// Stage 2: OPA structural evaluation
	opaInput := map[string]interface{}{
		"agent_id": input.AgentID,
		"tool_id":  input.ToolID,
		"tier":     input.Tier,
		"payload":  rawPayload,
	}

	results, err := g.query.Eval(ctx, rego.EvalInput(opaInput))
	if err != nil {
		return nil, fmt.Errorf("OPA evaluation error: %w", err)
	}

	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return &EvalDecision{Allow: false, Reason: "OPA returned no decision"}, nil
	}

	decision, ok := results[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return &EvalDecision{Allow: false, Reason: "unexpected OPA result shape"}, nil
	}

	allow, _ := decision["allow"].(bool)
	reason, _ := decision["reason"].(string)

	return &EvalDecision{Allow: allow, Reason: reason, CImpact: scope.CImpact}, nil
}

// detectInjection returns true and the matching pattern string if any
// known injection signature is found in the payload.
func (g *GuardrailEngine) detectInjection(payload string) (bool, string) {
	lower := strings.ToLower(payload)
	for _, pat := range g.patterns {
		if pat.MatchString(lower) {
			return true, pat.String()
		}
	}
	return false, ""
}

func loadScopeIndex(path string) (map[string]toolScope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Tools []toolScope `json:"tools"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	index := make(map[string]toolScope, len(manifest.Tools))
	for _, t := range manifest.Tools {
		index[t.ToolID] = t
	}
	return index, nil
}
