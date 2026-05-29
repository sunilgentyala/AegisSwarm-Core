package guardrails

import (
	"fmt"
	"strings"
)

// GoalVerifier checks an agent's proposed action against its declared
// operational goal to detect semantic goal drift caused by adversarial injection.
type GoalVerifier struct {
	registeredGoals map[string][]string
}

// NewGoalVerifier initialises a verifier with per-agent goal keyword sets.
func NewGoalVerifier(agentGoals map[string][]string) *GoalVerifier {
	return &GoalVerifier{registeredGoals: agentGoals}
}

// VerifyAction returns an error if the proposed action is semantically
// inconsistent with the agent's registered operational goal set.
// This is a lightweight heuristic layer; production deployments should
// pair this with an embedding-based similarity check.
func (v *GoalVerifier) VerifyAction(agentID, proposedAction string) error {
	goals, ok := v.registeredGoals[agentID]
	if !ok {
		return fmt.Errorf("agent %s has no registered goal set", agentID)
	}

	lower := strings.ToLower(proposedAction)
	for _, kw := range goals {
		if strings.Contains(lower, strings.ToLower(kw)) {
			return nil
		}
	}

	return fmt.Errorf("goal drift detected for agent %s: proposed action %q does not align with registered goals %v",
		agentID, proposedAction, goals)
}

// DefaultGoals provides conservative goal keyword sets for the manifest agents.
var DefaultGoals = map[string][]string{
	"orchestrator-alpha":    {"orchestrat", "coordinat", "delegat", "route", "assign"},
	"coder-agent-beta":      {"code", "write", "generate", "implement", "refactor", "test"},
	"compliance-agent-gamma": {"audit", "report", "compliance", "check", "validate", "review"},
	"data-writer-delta":     {"insert", "update", "write", "database", "record", "persist"},
}
