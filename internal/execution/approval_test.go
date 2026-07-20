package execution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestRequestHumanApproval_BlocksWithoutToken proves that the escalation
// gate genuinely halts execution when no approval token is ever submitted,
// rather than the old stub behavior of logging a message and returning nil
// immediately (silent auto-approval). If the fix regressed to the old
// behavior, this test would observe an elapsed time near zero and a nil
// error; instead it must observe a real block for (approximately) the
// full context deadline and a non-nil error.
func TestRequestHumanApproval_BlocksWithoutToken(t *testing.T) {
	operatorPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	gate := NewApprovalGate(operatorPub)
	c := &Conductor{logger: zap.NewNop(), approvals: gate}

	const window = 300 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), window)
	defer cancel()

	start := time.Now()
	err = c.requestHumanApproval(ctx, ToolRequest{AgentID: "agent-x", ToolID: "delete_resource"}, 0.95)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("SECURITY FAILURE: escalated action was approved with no approval token submitted (auto-approval regression)")
	}
	if elapsed < window-50*time.Millisecond {
		t.Fatalf("requestHumanApproval returned after only %v, expected it to actually block for close to %v; "+
			"this indicates execution is NOT genuinely frozen", elapsed, window)
	}
}

// TestRequestHumanApproval_RejectsForgedToken proves that a token signed
// by any key other than the configured operator's key — an attacker's own
// key, standing in for a forged/unsigned clearance — is cryptographically
// rejected and never unblocks the waiting caller.
func TestRequestHumanApproval_RejectsForgedToken(t *testing.T) {
	operatorPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("operator keygen: %v", err)
	}
	_, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("attacker keygen: %v", err)
	}

	gate := NewApprovalGate(operatorPub)
	c := &Conductor{logger: zap.NewNop(), approvals: gate}

	notify := make(chan PendingApproval, 1)
	gate.SetNotifyChannel(notify)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req := ToolRequest{AgentID: "agent-x", ToolID: "delete_resource"}

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.requestHumanApproval(ctx, req, 0.95)
	}()

	var pending PendingApproval
	select {
	case pending = <-notify:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for escalation to register as pending")
	}

	forged := SignApprovalToken(attackerPriv, pending.RequestID, req.AgentID, req.ToolID, time.Minute)
	if submitErr := gate.Submit(forged); submitErr == nil {
		t.Fatal("SECURITY FAILURE: a token signed by a non-operator key was accepted by Submit")
	}

	// Also try a token with a garbage/empty signature (simulating an
	// entirely unsigned clearance attempt).
	unsigned := &ApprovalToken{
		RequestID: pending.RequestID,
		AgentID:   req.AgentID,
		ToolID:    req.ToolID,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Minute),
	}
	if submitErr := gate.Submit(unsigned); submitErr == nil {
		t.Fatal("SECURITY FAILURE: an unsigned token was accepted by Submit")
	}

	select {
	case err = <-errCh:
		if err == nil {
			t.Fatal("SECURITY FAILURE: requestHumanApproval unblocked despite only forged/unsigned tokens being submitted")
		}
	case <-time.After(2500 * time.Millisecond):
		t.Fatal("requestHumanApproval never returned after context should have expired")
	}
}

// TestRequestHumanApproval_AcceptsValidSignedToken proves the positive
// case: a token genuinely signed by the configured operator's private key,
// for the exact pending request, unblocks execution and clears the
// escalation.
func TestRequestHumanApproval_AcceptsValidSignedToken(t *testing.T) {
	operatorPub, operatorPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("operator keygen: %v", err)
	}
	gate := NewApprovalGate(operatorPub)
	c := &Conductor{logger: zap.NewNop(), approvals: gate}

	notify := make(chan PendingApproval, 1)
	gate.SetNotifyChannel(notify)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := ToolRequest{AgentID: "agent-x", ToolID: "delete_resource"}

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.requestHumanApproval(ctx, req, 0.95)
	}()

	var pending PendingApproval
	select {
	case pending = <-notify:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for escalation to register as pending")
	}

	valid := SignApprovalToken(operatorPriv, pending.RequestID, req.AgentID, req.ToolID, time.Minute)
	if submitErr := gate.Submit(valid); submitErr != nil {
		t.Fatalf("expected a genuinely operator-signed token to be accepted, got: %v", submitErr)
	}

	select {
	case err = <-errCh:
		if err != nil {
			t.Fatalf("expected escalation to clear after a valid signed token, got error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("requestHumanApproval did not unblock after a validly signed token was submitted")
	}
}

// TestApprovalGate_ExpiredTokenRejected proves that an otherwise validly
// signed token is still rejected once past its ExpiresAt.
func TestApprovalGate_ExpiredTokenRejected(t *testing.T) {
	operatorPub, operatorPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	gate := NewApprovalGate(operatorPub)

	notify := make(chan PendingApproval, 1)
	gate.SetNotifyChannel(notify)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	req := PendingApproval{RequestID: "req-expired-1", AgentID: "agent-x", ToolID: "delete_resource", CreatedAt: time.Now()}
	go func() { _, _ = gate.Await(ctx, req) }()
	<-notify

	// Signed, but already expired.
	expired := SignApprovalToken(operatorPriv, req.RequestID, req.AgentID, req.ToolID, -time.Minute)
	if err := gate.Submit(expired); err == nil {
		t.Fatal("SECURITY FAILURE: an expired token was accepted")
	}
}
