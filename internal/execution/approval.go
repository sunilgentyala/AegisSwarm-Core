package execution

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"
)

// ApprovalToken is a cryptographically signed clearance issued by an
// authenticated human operator for exactly one escalated tool request.
// Possession of the token's bytes is not sufficient to unblock execution:
// its ed25519 signature must verify against the operator's public key, it
// must not be expired, and its RequestID/AgentID/ToolID must match the
// pending escalation it claims to authorize.
type ApprovalToken struct {
	RequestID string
	AgentID   string
	ToolID    string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Signature []byte // ed25519 signature over CanonicalPayload()
}

// CanonicalPayload returns the exact byte sequence that an operator's
// private key signs, and that Submit verifies the signature against.
// Every field that identifies *what* is being approved is included, so a
// signature over one request cannot be replayed against another.
func (t *ApprovalToken) CanonicalPayload() []byte {
	return []byte(fmt.Sprintf("aegisswarm-approval-v1|%s|%s|%s|%d|%d",
		t.RequestID, t.AgentID, t.ToolID, t.IssuedAt.UnixNano(), t.ExpiresAt.UnixNano()))
}

// SignApprovalToken builds and signs an ApprovalToken using an operator's
// ed25519 private key. This is what a real ITSM/on-call tool would do
// server-side after an operator authenticates and clicks "approve" — the
// transport that gets the token from that tool back into AegisSwarm
// (PagerDuty/ServiceNow webhook, CLI, etc.) is the documented integration
// point described in the README; this function performs the actual
// cryptographic signing step.
func SignApprovalToken(priv ed25519.PrivateKey, requestID, agentID, toolID string, ttl time.Duration) *ApprovalToken {
	now := time.Now().UTC()
	tok := &ApprovalToken{
		RequestID: requestID,
		AgentID:   agentID,
		ToolID:    toolID,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	}
	tok.Signature = ed25519.Sign(priv, tok.CanonicalPayload())
	return tok
}

// PendingApproval describes an escalated request that is currently
// blocking a goroutine inside Await, waiting for a signed operator token.
type PendingApproval struct {
	RequestID string
	AgentID   string
	ToolID    string
	RiskScore float64
	CreatedAt time.Time
}

// ApprovalGate is the real, blocking human-in-the-loop clearance mechanism
// for escalated tool calls. Unlike the previous stub — which logged a
// message and returned nil immediately, silently auto-approving every
// escalation — ApprovalGate genuinely halts the calling goroutine in Await
// until a validly signed ApprovalToken for that exact request is submitted
// via Submit, or the caller's context deadline elapses.
//
// What is real here: the blocking wait (Await does not return until a
// token arrives or the deadline passes) and the cryptographic clearance
// check (ed25519 signature verification against a known operator public
// key — not a string comparison).
//
// What remains a documented integration point, not implemented here: the
// transport that notifies a human operator and carries their decision back
// (e.g., a PagerDuty/ServiceNow webhook, a Slack action, or an internal
// approvals UI). Any of those can call Submit once the operator has
// authenticated and signed off; ApprovalGate does not care how the token
// physically arrived, only whether it verifies.
type ApprovalGate struct {
	mu       sync.Mutex
	operator ed25519.PublicKey
	pending  map[string]chan *ApprovalToken
	meta     map[string]PendingApproval
	notifyCh chan PendingApproval
}

// NewApprovalGate constructs a gate that only accepts tokens signed by
// operatorPubKey. A nil or empty key means no token can ever verify —
// Submit will always fail, which is the deliberate fail-closed behavior
// for a misconfigured deployment.
func NewApprovalGate(operatorPubKey ed25519.PublicKey) *ApprovalGate {
	return &ApprovalGate{
		operator: operatorPubKey,
		pending:  make(map[string]chan *ApprovalToken),
		meta:     make(map[string]PendingApproval),
	}
}

// SetNotifyChannel installs an optional channel that receives a copy of
// every PendingApproval the moment Await starts waiting on it. It exists
// so that an approvals dashboard (or a test) can observe an escalation as
// it happens rather than polling Pending(). The send is non-blocking: a
// full or nil channel never stalls the caller of Await.
func (g *ApprovalGate) SetNotifyChannel(ch chan PendingApproval) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.notifyCh = ch
}

// Await registers p as a pending escalation and blocks until a matching,
// validly signed ApprovalToken is delivered via Submit, or until ctx is
// done. This is the actual freeze: there is no code path in Await that
// returns success without a verified token having been submitted for this
// exact RequestID.
func (g *ApprovalGate) Await(ctx context.Context, p PendingApproval) (*ApprovalToken, error) {
	ch := make(chan *ApprovalToken, 1)

	g.mu.Lock()
	g.pending[p.RequestID] = ch
	g.meta[p.RequestID] = p
	notify := g.notifyCh
	g.mu.Unlock()

	if notify != nil {
		select {
		case notify <- p:
		default:
		}
	}

	defer func() {
		g.mu.Lock()
		delete(g.pending, p.RequestID)
		delete(g.meta, p.RequestID)
		g.mu.Unlock()
	}()

	select {
	case tok := <-ch:
		return tok, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("approval window closed with no valid clearance: %w", ctx.Err())
	}
}

// Pending returns a snapshot of every escalation currently blocked in
// Await, for dashboards or diagnostics.
func (g *ApprovalGate) Pending() []PendingApproval {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]PendingApproval, 0, len(g.meta))
	for _, p := range g.meta {
		out = append(out, p)
	}
	return out
}

// Submit is how a verified operator decision reaches ApprovalGate. It
// performs the real cryptographic clearance check:
//  1. The token must not be expired.
//  2. Its ed25519 signature must verify against the configured operator
//     public key — a token signed by any other key (a forgery, or an
//     attacker's own key) is rejected here, not accepted.
//  3. It must match a currently pending RequestID/AgentID/ToolID; a token
//     for an unknown, already-resolved, or mismatched request is rejected.
//
// Only if all three hold does the matching Await call unblock.
func (g *ApprovalGate) Submit(tok *ApprovalToken) error {
	if tok == nil {
		return fmt.Errorf("nil approval token")
	}
	if len(g.operator) != ed25519.PublicKeySize {
		return fmt.Errorf("approval gate has no valid operator public key configured; refusing all tokens (fail closed)")
	}
	if time.Now().UTC().After(tok.ExpiresAt) {
		return fmt.Errorf("approval token for request %s has expired", tok.RequestID)
	}
	if len(tok.Signature) == 0 || !ed25519.Verify(g.operator, tok.CanonicalPayload(), tok.Signature) {
		return fmt.Errorf("approval token signature verification failed for request %s", tok.RequestID)
	}

	g.mu.Lock()
	ch, ok := g.pending[tok.RequestID]
	meta, metaOK := g.meta[tok.RequestID]
	g.mu.Unlock()
	if !ok || !metaOK {
		return fmt.Errorf("no pending approval request %s (already resolved, expired, or unknown)", tok.RequestID)
	}
	if meta.AgentID != tok.AgentID || meta.ToolID != tok.ToolID {
		return fmt.Errorf("approval token agent/tool does not match pending request %s", tok.RequestID)
	}

	select {
	case ch <- tok:
		return nil
	default:
		return fmt.Errorf("approval request %s already resolved", tok.RequestID)
	}
}
