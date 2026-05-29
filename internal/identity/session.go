package identity

import (
	"fmt"
	"sync"
	"time"
)

// SessionState holds time-bounded execution context for a single agent run.
// Sessions expire automatically; any tool call after expiry is rejected.
type SessionState struct {
	mu          sync.RWMutex
	SessionID   string
	AgentID     string
	Tier        int
	IssuedAt    time.Time
	ExpiresAt   time.Time
	TokenBudget int
	UsedTokens  int
	Terminated  bool
}

// NewSession constructs a bounded session for the given agent.
func NewSession(sessionID, agentID string, tier, tokenBudget, ttlSeconds int) *SessionState {
	now := time.Now().UTC()
	return &SessionState{
		SessionID:   sessionID,
		AgentID:     agentID,
		Tier:        tier,
		IssuedAt:    now,
		ExpiresAt:   now.Add(time.Duration(ttlSeconds) * time.Second),
		TokenBudget: tokenBudget,
	}
}

// IsAlive returns true if the session has not expired and has not been terminated.
func (s *SessionState) IsAlive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.Terminated && time.Now().UTC().Before(s.ExpiresAt)
}

// ConsumeTokens deducts n tokens from the session budget.
func (s *SessionState) ConsumeTokens(n int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.UsedTokens+n > s.TokenBudget {
		return fmt.Errorf("token budget exceeded: used=%d requested=%d budget=%d",
			s.UsedTokens, n, s.TokenBudget)
	}
	s.UsedTokens += n
	return nil
}

// Terminate marks the session as ended, blocking further tool execution.
func (s *SessionState) Terminate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Terminated = true
}

// RemainingBudget returns tokens remaining in this session.
func (s *SessionState) RemainingBudget() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.TokenBudget - s.UsedTokens
}
