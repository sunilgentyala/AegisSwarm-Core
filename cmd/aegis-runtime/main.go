// AegisSwarm Runtime - Zero-Trust Multi-Agent Orchestration Entry Point
// Author: Sunil Gentyala | HCLTECH
// Framework: AegisSwarm v1.0 | CSA Agentic Trust Framework aligned
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sunilgentyala/aegisswarm-core/internal/execution"
	"github.com/sunilgentyala/aegisswarm-core/internal/guardrails"
	"github.com/sunilgentyala/aegisswarm-core/internal/identity"
)

const (
	defaultConfigPath   = "./configs/agents_manifest.json"
	defaultScopePath    = "./configs/tool_scopes.json"
	defaultPolicyDir    = "./policies"
	defaultOTLPEndpoint = "localhost:4317"
)

func main() {
	configPath := flag.String("config", defaultConfigPath, "Path to agent manifest JSON")
	scopePath := flag.String("scopes", defaultScopePath, "Path to tool scopes JSON")
	policyDir := flag.String("policies", defaultPolicyDir, "Directory containing OPA .rego policy files")
	otlpEndpoint := flag.String("otlp", defaultOTLPEndpoint, "OpenTelemetry OTLP gRPC endpoint")
	agentID := flag.String("agent", "", "Agent ID to bootstrap (required)")
	trustBundlePath := flag.String("trust-bundle", "", "Path to a PEM file of CA certificates trusted for peer SPIFFE-SVID verification (see internal/identity/spiffe.go). Empty means no peer will ever validate (fail closed).")
	operatorPubKeyHex := flag.String("operator-pubkey", "", "Hex-encoded ed25519 public key of the human operator authorized to sign escalation approval tokens (see internal/execution/approval.go). Empty means escalated actions fail closed rather than auto-approve.")
	flag.Parse()

	if *agentID == "" {
		fmt.Fprintln(os.Stderr, "error: --agent flag is required")
		flag.Usage()
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Printf("AegisSwarm runtime starting | agent=%s | config=%s | scopes=%s | policies=%s | otlp=%s",
		*agentID, *configPath, *scopePath, *policyDir, *otlpEndpoint)

	// --- Identity layer -----------------------------------------------
	// Loads a CA trust bundle (if provided) so that ValidatePeer performs
	// real X.509 chain verification rather than failing open. Speaking the
	// SPIRE Workload API wire protocol to fetch SVIDs/bundles at runtime
	// remains a documented integration point (see README); here the
	// bundle is loaded from a static PEM file, which is what a SPIRE agent
	// socket would otherwise supply.
	trustBundle, err := loadTrustBundle(*trustBundlePath)
	if err != nil {
		log.Fatalf("failed to load trust bundle: %v", err)
	}
	idManager, err := identity.NewSPIFFEManager(ctx, *agentID, trustBundle)
	if err != nil {
		log.Fatalf("failed to initialize identity manager: %v", err)
	}
	defer idManager.Close()

	// --- Guardrail engine (OPA + injection filter) ----------------------
	guardrailEngine, err := guardrails.NewGuardrailEngine(*policyDir, *scopePath)
	if err != nil {
		log.Fatalf("failed to initialize guardrail engine: %v", err)
	}

	// --- Conductor (risk scoring, escalation, sandboxed dispatch) -------
	conductor, err := execution.NewConductor(*configPath, idManager, guardrailEngine)
	if err != nil {
		log.Fatalf("failed to initialize conductor: %v", err)
	}

	// --- Human approval gate --------------------------------------------
	// Wires the cryptographic clearance mechanism described in
	// internal/execution/approval.go. Without an operator public key
	// configured, escalated actions fail closed rather than silently
	// auto-approving.
	if *operatorPubKeyHex != "" {
		pubKey, err := decodeOperatorPubKey(*operatorPubKeyHex)
		if err != nil {
			log.Fatalf("invalid --operator-pubkey: %v", err)
		}
		conductor.SetApprovalGate(execution.NewApprovalGate(pubKey))
		log.Printf("human approval gate configured with operator public key")
	} else {
		log.Printf("WARNING: no --operator-pubkey configured; escalated actions will fail closed (denied), not auto-approved")
	}

	// otlpEndpoint is accepted for OpenTelemetry trace export wiring
	// (internal/telemetry.InitTracerProvider); establishing the OTLP gRPC
	// connection at startup is left to deployment-specific bootstrapping
	// and is not required for the guardrail/escalation/sandbox path above.
	_ = otlpEndpoint

	log.Printf("AegisSwarm runtime ready | agent=%s | tier=%d", *agentID, conductor.AgentTier(*agentID))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	conductor.Shutdown(shutdownCtx)

	log.Printf("AegisSwarm runtime shutdown complete | agent=%s", *agentID)
}

// loadTrustBundle reads a PEM file of CA certificates. An empty path
// returns a nil pool, which SPIFFEManager.ValidatePeer treats as
// fail-closed (no peer certificate will ever verify).
func loadTrustBundle(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trust bundle %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("no valid PEM certificates found in %s", path)
	}
	return pool, nil
}

// decodeOperatorPubKey parses a hex-encoded ed25519 public key.
func decodeOperatorPubKey(hexKey string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("not valid hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}
