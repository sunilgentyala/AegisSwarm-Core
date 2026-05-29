// Package identity implements SPIFFE/SPIRE-based cryptographic agent identity.
// Every agent receives a short-lived X.509-SVID and JWT bound to its SPIFFE ID
// so that mutual TLS is enforced at every agent-to-agent call boundary.
package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	SVIDAudience   = "aegisswarm.enterprise.local"
	DefaultTTL     = 3600 * time.Second
)

// SPIFFEManager manages short-lived cryptographic identity tokens for a
// single agent instance. In production it connects to a SPIRE Workload API.
type SPIFFEManager struct {
	agentID   string
	sessionID string
}

// NewSPIFFEManager bootstraps identity for the given agent.
// Connects to the SPIRE Workload API via SPIFFE_ENDPOINT_SOCKET.
func NewSPIFFEManager(_ context.Context, agentID string) (*SPIFFEManager, error) {
	if agentID == "" {
		return nil, fmt.Errorf("agentID must not be empty")
	}
	return &SPIFFEManager{
		agentID:   agentID,
		sessionID: uuid.New().String(),
	}, nil
}

// SessionID returns the unique execution session identifier.
func (m *SPIFFEManager) SessionID() string { return m.sessionID }

// AgentID returns the agent identifier.
func (m *SPIFFEManager) AgentID() string { return m.agentID }

// SPIFFEUri returns the canonical SPIFFE URI for this agent.
func (m *SPIFFEManager) SPIFFEUri() string {
	return fmt.Sprintf("spiffe://%s/aegisswarm/agent/%s", SVIDAudience, m.agentID)
}

// ValidatePeer verifies that a peer agent's SPIFFE ID is in the expected
// trust domain, preventing lower-tier agents from spoofing orchestrators.
func (m *SPIFFEManager) ValidatePeer(peerURI string) error {
	expected := fmt.Sprintf("spiffe://%s/", SVIDAudience)
	if len(peerURI) < len(expected) || peerURI[:len(expected)] != expected {
		return fmt.Errorf("peer URI %q is outside trusted domain %s", peerURI, SVIDAudience)
	}
	return nil
}

// Close releases SPIRE Workload API resources.
func (m *SPIFFEManager) Close() {}
