// Package identity implements SPIFFE/SPIRE-based cryptographic agent identity.
// Every agent receives a short-lived X.509-SVID and JWT bound to its SPIFFE ID
// so that mutual TLS is enforced at every agent-to-agent call boundary.
package identity

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	SVIDAudience = "aegisswarm.enterprise.local"
	DefaultTTL   = 3600 * time.Second
)

// SPIFFEManager manages short-lived cryptographic identity for a single
// agent instance and validates the identity of peers it talks to.
//
// In a full production deployment this connects to a SPIRE Workload API
// (over SPIFFE_ENDPOINT_SOCKET) to obtain rotating X.509-SVIDs and the
// current trust bundle. Speaking that Workload API wire protocol is a
// documented integration point, not implemented by this reference
// framework (see README). What this type does implement for real is the
// verification side: given a peer's X.509 certificate and a trust bundle
// (which, in production, is exactly what the Workload API would supply),
// it performs genuine certificate-chain verification and SPIFFE URI SAN
// checking — not a string comparison of caller-asserted text.
type SPIFFEManager struct {
	agentID     string
	sessionID   string
	trustDomain string
	trustBundle *x509.CertPool
}

// NewSPIFFEManager bootstraps identity for the given agent. trustBundle is
// the set of CA certificates that a peer's X.509-SVID must chain to in
// order to be accepted by ValidatePeer. Passing a nil trustBundle is
// allowed but means ValidatePeer will fail closed for every peer — no
// certificate will ever verify against an empty root pool, by design,
// rather than falling back to any weaker check.
func NewSPIFFEManager(_ context.Context, agentID string, trustBundle *x509.CertPool) (*SPIFFEManager, error) {
	if agentID == "" {
		return nil, fmt.Errorf("agentID must not be empty")
	}
	return &SPIFFEManager{
		agentID:     agentID,
		sessionID:   uuid.New().String(),
		trustDomain: SVIDAudience,
		trustBundle: trustBundle,
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

// ValidatePeer performs real X.509 certificate-based SPIFFE peer
// validation on an mTLS peer certificate:
//
//  1. The certificate must chain to a CA in the configured trust bundle.
//     x509.Certificate.Verify performs genuine signature verification up
//     the chain plus validity-window checking; a self-signed certificate
//     or one issued by an untrusted CA fails here regardless of what its
//     Subject or SAN fields claim.
//  2. The certificate must carry exactly one URI SAN, it must parse as a
//     spiffe:// URI, and its host must equal the expected trust domain.
//
// This replaces a previous implementation that took a caller-supplied
// string and only compared its prefix against the expected trust domain
// string — no certificate, no signature, no chain-of-trust check at all,
// meaning any caller could claim any SPIFFE identity just by asserting the
// text. Here, the identity claim (the URI SAN) is only trusted once it has
// been read out of a certificate whose signature chain has been
// cryptographically verified.
func (m *SPIFFEManager) ValidatePeer(peerCert *x509.Certificate) error {
	if peerCert == nil {
		return fmt.Errorf("no peer certificate presented")
	}
	if m.trustBundle == nil {
		return fmt.Errorf("no trust bundle configured; refusing to validate any peer (fail closed)")
	}

	opts := x509.VerifyOptions{
		Roots:     m.trustBundle,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := peerCert.Verify(opts); err != nil {
		return fmt.Errorf("peer certificate failed chain verification: %w", err)
	}

	if len(peerCert.URIs) != 1 {
		return fmt.Errorf("peer certificate must carry exactly one URI SAN, found %d", len(peerCert.URIs))
	}

	peerURI := peerCert.URIs[0]
	if peerURI.Scheme != "spiffe" {
		return fmt.Errorf("peer URI SAN %q is not a spiffe:// URI", peerURI.String())
	}
	if peerURI.Host != m.trustDomain {
		return fmt.Errorf("peer URI %q is outside trusted domain %s", peerURI.String(), m.trustDomain)
	}

	return nil
}

// Close releases SPIRE Workload API resources.
func (m *SPIFFEManager) Close() {}
