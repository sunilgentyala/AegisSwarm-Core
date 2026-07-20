# AegisSwarm-Core

**Zero-Trust Security and Governance Reference Architecture for Autonomous Multi-Agent AI Systems**

[![Policy CI](https://github.com/sunilgentyala/AegisSwarm-Core/actions/workflows/policy-ci.yml/badge.svg)](https://github.com/sunilgentyala/AegisSwarm-Core/actions/workflows/policy-ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![CSA Published](https://img.shields.io/badge/Published%20by-CSA-red.svg)](https://cloudsecurityalliance.org/blog/2026/06/24/securing-the-swarm-governance-attack-surfaces-and-zero-trust-architectures-in-multi-agent-ai-environments)
[![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP-Agentic%20Top%2010%20Aligned-orange.svg)](#threat-coverage)
[![NIST AI RMF](https://img.shields.io/badge/NIST-AI%20RMF%201.0-8b5cf6.svg)](#csa-alignment)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

Author: Sunil Gentyala | HCLTECH (HCL America Inc.) | sunil.gentyala@ieee.org  
Framework Version: 1.0.0  
CSA Agentic Trust Framework Aligned | OWASP Top 10 Risks and Mitigations for Agentic AI Security (Dec 2025) | NIST AI RMF 1.0

> **Published by the Cloud Security Alliance (CSA), June 24, 2026.**  
> Read the article: ["Securing the Swarm: Governance, Attack Surfaces, and Zero-Trust Architectures in Multi-Agent AI Environments"](https://cloudsecurityalliance.org/blog/2026/06/24/securing-the-swarm-governance-attack-surfaces-and-zero-trust-architectures-in-multi-agent-ai-environments) by Sunil Gentyala.
>
> **Project site:** [sunilgentyala.github.io/AegisSwarm-Core](https://sunilgentyala.github.io/AegisSwarm-Core/)

---

## Overview

AegisSwarm-Core is the open-source reference implementation accompanying the CSA article *"Securing the Swarm: Governance, Attack Surfaces, and Zero-Trust Architectures in Multi-Agent AI Environments"*.

Enterprise AI has moved beyond isolated LLM prompts into autonomous Multi-Agent Systems (MAS), where specialized digital workers decompose, delegate, and execute tasks without per-step human oversight. While this unlocks dramatic operational velocity, it introduces execution-plane attack surfaces that legacy perimeter defenses cannot address.

AegisSwarm wraps a strict, deterministic boundary layer around autonomous agent networks. Rather than modifying model weights or relying on alignment alone, it intercepts, evaluates, and audits every agentic action in real time using four independent subsystems.

---

## Why AegisSwarm-Core

- **Closes the gap legacy security tools miss.** Firewalls, WAFs, and IAM were built for static clients, not autonomous agents that plan, delegate, and call tools on their own; AegisSwarm governs the agent execution plane directly.
- **Maps to a named threat model, not a generic checklist.** Every control traces to a specific entry in the OWASP Top 10 for Agentic Applications (ASI01-ASI05), so coverage gaps are visible rather than assumed.
- **Identity-first, not key-based.** SPIFFE/SPIRE short-lived SVIDs and mutual TLS replace static API keys between agents, removing the most common path to "Confused Deputy" privilege escalation.
- **Policy-as-code, not hardcoded rules.** OPA/Rego policies for autonomy tiers and tool access can be reviewed, versioned, and tested in CI like any other code, instead of being buried in application logic.
- **Quantifies risk instead of guessing.** The `Rs = C_impact x (1 - P_conf)` scoring model gives a deterministic, auditable trigger for human-in-the-loop escalation rather than relying on the agent's own confidence claims.
- **Built for audit from day one.** Every stage emits HMAC-signed, OpenTelemetry-traced records, so incident response and compliance reviews have a verifiable trail instead of best-effort logging.
- **Standards-aligned, not a one-off framework.** Maps directly to the CSA Agentic Trust Framework, CSA Cloud Controls Matrix v4.1, and NIST AI RMF, so adopting it supports existing compliance programs rather than creating a new one.
- **Open and inspectable.** Apache 2.0 licensed reference implementation in Go, with vulnerability simulation tests included, so teams can verify the guardrails actually hold before trusting them in production.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AegisSwarm Runtime                           │
│                                                                     │
│   Incoming Data / Tool Request                                      │
│           │                                                         │
│           ▼                                                         │
│   ┌───────────────────────┐                                         │
│   │  Aegis Data Ingestion │  PII tokenization, dual-stage           │
│   │  Gateway              │  semantic injection classifier          │
│   └──────────┬────────────┘                                         │
│              │                                                      │
│              ▼                                                      │
│   ┌───────────────────────┐                                         │
│   │  Cryptographic        │  SPIFFE/SPIRE short-lived SVIDs,        │
│   │  Identity Layer       │  mutual agent-to-agent mTLS handshake   │
│   └──────────┬────────────┘                                         │
│              │                                                      │
│              ▼                                                      │
│   ┌───────────────────────┐                                         │
│   │  OPA Guard Control    │  Rego policy evaluation, tier-based     │
│   │  (Aegis Governance)   │  tool access, globally blocked ops      │
│   └──────────┬────────────┘                                         │
│              │                                                      │
│              ▼                                                      │
│   ┌───────────────────────┐     Rs ≥ threshold?                     │
│   │  Rs Risk Metric &     │  ──────────────────► Human Approval     │
│   │  Escalation Runtime   │                       Gate (HITL)       │
│   └──────────┬────────────┘                                         │
│              │                                                      │
│              ▼                                                      │
│   ┌───────────────────────┐                                         │
│   │  Sandboxed Tool       │  Time-bounded, whitelist-only           │
│   │  Executor             │  tool dispatch                          │
│   └───────────────────────┘                                         │
│                                                                     │
│   OpenTelemetry + HMAC-Signed Audit Trail (all stages)              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## The Four Subsystems

### 1. Aegis Data Ingestion Gateway
All incoming data passes through PII/PHI tokenization and a dual-stage semantic classifier before entering an agent's context window. This is the primary defense against Indirect Prompt Injection (OWASP ASI01).

### 2. Cryptographic Identity Layer (Aegis-Identity)
Every agent instance receives a short-lived X.509-SVID and JWT-SVID via [SPIFFE/SPIRE](https://spiffe.io/). Static API keys are eliminated. Agent-to-agent calls require mutual TLS handshakes, preventing the "Confused Deputy" privilege escalation pattern (OWASP ASI03).

`internal/identity/spiffe.go`'s `SPIFFEManager.ValidatePeer` performs real X.509 verification: it checks the peer certificate's chain against a configured CA trust bundle (`crypto/x509.Certificate.Verify`) and then reads the SPIFFE URI out of the certificate's URI SAN, comparing it against the expected trust domain. A certificate with the right-looking `spiffe://` URI text but no valid signature chain — self-signed, or signed by an untrusted CA — is rejected; see `internal/identity/spiffe_test.go` for adversarial tests proving this. **Documented integration point, not implemented here:** speaking the SPIRE Workload API wire protocol to fetch rotating SVIDs and trust bundles over `SPIFFE_ENDPOINT_SOCKET` at runtime. This reference implementation loads a static PEM trust bundle (`--trust-bundle`) instead of that live socket; wiring in a real `go-spiffe` Workload API client is left as the production integration step. With no trust bundle configured, `ValidatePeer` fails closed for every peer rather than falling back to a weaker check.

### 3. OPA Guard Control
Before any tool executes, the structured request payload is evaluated against Rego policies in [Open Policy Agent](https://www.openpolicyagent.org/). Policies enforce autonomy tiers, globally blocked tools (`execute_shell`, `external_transfer`), and network access controls.

Once a request clears policy, `internal/execution/sandbox.go`'s `RunInSandbox` dispatches it to a whitelisted handler (`read_file`, `list_directory`, `query_audit_log`, `generate_report`, `run_tests` — anything else, including `execute_shell`, is rejected because it was never registered). Every handler now does real, verifiable work instead of returning a placeholder status: `read_file`/`list_directory` perform real filesystem I/O confined to a sandbox root (`resolveInSandbox` rejects absolute paths, `../` traversal, and symlink escapes before touching disk); `generate_report` writes a real file under `<sandbox-root>/reports`; `query_audit_log` reads real JSON-lines entries from an audit log file; `run_tests` genuinely shells out to `go test` via `exec.CommandContext`. The time budget is real too — `RunInSandboxWithTimeout` derives a `context.WithTimeout` that is passed all the way down, so a handler that runs long is raced against that deadline, and for `run_tests` the underlying OS process is actually killed on timeout, not just abandoned. See `internal/execution/sandbox_test.go` for tests proving a path-traversal read is rejected, a whitelisted read returns real content, and a slow handler (including a real `go test` subprocess) is actually cancelled.

### 4. Escalation and Human-in-the-Loop Runtime
AegisSwarm computes a dynamic risk score for every proposed transaction:

```
Rs = C_impact × (1 − P_conf)
```

Where `C_impact` is the configured critical cost of the target resource and `P_conf` is the agent's internal confidence score. If `Rs` exceeds the agent's configured threshold, execution freezes until an authenticated human operator provides cryptographic clearance.

This is implemented in `internal/execution/approval.go`'s `ApprovalGate`. `Conductor.requestHumanApproval` blocks on `ApprovalGate.Await` and returns only when a matching `ApprovalToken` is submitted whose `ed25519` signature verifies against a configured operator public key (`crypto/ed25519`, not a string comparison) and which has not expired; a forged token (signed with the wrong key), an unsigned token, or no token at all all leave the caller blocked until the context deadline, at which point the action is denied — **fail closed**, not auto-approved. If no `ApprovalGate` is configured at all (e.g. `aegis-runtime` was started without `--operator-pubkey`), escalations are denied immediately rather than silently passing through. See `internal/execution/approval_test.go` for tests proving: (a) an escalated action stays blocked with no token submitted, (b) a token signed by a non-operator key is rejected and never unblocks execution, and (c) a token genuinely signed by the operator's private key does unblock it.

**Documented integration point, not implemented here:** the transport that notifies an on-call human and carries their decision back into the process — a PagerDuty/ServiceNow webhook, a Slack interactive message, an internal approvals dashboard. Any of those can call `ApprovalGate.Submit` once an operator has authenticated and signed off; `ApprovalGate` does not care how the token physically arrived, only whether it cryptographically verifies. What this repository implements for real is the blocking wait and the signature verification, not the ITSM webhook itself.

---

## Threat Coverage

| OWASP Agentic Top 10 (Dec 2025) | AegisSwarm Mitigation |
|---|---|
| ASI01: Agent Goal Hijack | Dual-stage injection filter + GoalVerifier semantic check |
| ASI02: Tool Misuse & Exploitation | OPA tier policies + globally blocked tool registry + sandbox |
| ASI03: Agent Identity & Privilege Abuse | SPIFFE/SPIRE mTLS + JWT-SVID peer validation |
| ASI04: Resource Overconsumption | Per-session token budget + rate limiting per tool |
| ASI05: Supply Chain Compromise | OPA policy-as-code CI gate on every manifest change |

---

## Repository Structure

```
AegisSwarm-Core/
├── .github/
│   └── workflows/
│       └── policy-ci.yml           # CI: OPA lint/test, Go tests, govulncheck
├── cmd/
│   └── aegis-runtime/
│       └── main.go                 # Runtime bootstrap entry point
├── configs/
│   ├── agents_manifest.json        # Agent capability registry (tiers, tools, TTL)
│   └── tool_scopes.json            # RBAC mappings and C_impact values per tool
├── internal/
│   ├── identity/
│   │   ├── spiffe.go               # SPIFFE/SPIRE identity and JWT-SVID management
│   │   └── session.go              # Short-lived session state and token budgets
│   ├── execution/
│   │   ├── conductor.go            # State graph orchestration + Rs risk scoring
│   │   ├── approval.go             # Ed25519-signed human approval gate (HITL)
│   │   └── sandbox.go              # Whitelist-only time-bounded tool executor
│   ├── guardrails/
│   │   ├── injection_filter.go     # Regex + OPA dual-stage injection detection
│   │   └── goal_verifier.go        # Semantic goal drift detection
│   └── telemetry/
│       ├── auditor.go              # HMAC-signed audit records + OTel tracing
│       └── metrics.go              # Prometheus metrics for all runtime events
├── policies/
│   ├── autonomy_tiers.rego         # Tier-based tool access (Tier 1–4)
│   └── tool_access.rego            # Network access control (SSRF prevention)
├── tests/
│   ├── vulnerability_simulation/
│   │   └── goal_hijack_test.go     # ASI01, ASI02, ASI03 attack simulations
│   └── integration_test.go         # Core guardrail integration tests
├── README.md
└── go.mod
```

---

## Quick Start

### Prerequisites
- Go 1.22+
- [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa) (for policy development)
- OpenTelemetry collector (optional, for trace export)
- A CA-signed X.509 trust bundle and an ed25519 operator keypair for the identity layer and the human-approval gate respectively (see `--trust-bundle` / `--operator-pubkey` below). A live [SPIRE](https://spiffe.io/docs/latest/spire-about/spire-concepts/) deployment is the production source for the former; connecting to its Workload API directly is a documented integration point not yet wired into this reference implementation.

### Run the tests

```bash
# Clone the repo
git clone https://github.com/sunilgentyala/AegisSwarm-Core.git
cd AegisSwarm-Core

# Download Go dependencies
go mod download

# Run guardrail integration tests
go test ./tests/... -v

# Run vulnerability simulation tests (ASI01, ASI02, ASI03)
go test ./tests/vulnerability_simulation/... -v

# Run the sandbox, escalation, and identity unit tests — these are the
# adversarial tests for the three subsystems described above: forged/
# unsigned approval tokens, path-traversal reads, and self-signed or
# wrong-CA SPIFFE certificates are all exercised and must be rejected.
go test ./internal/execution/... ./internal/identity/... -v

# Run every test in the module
go test ./...

# Lint and test OPA policies
opa check policies/
opa test policies/ -v
```

### Run the runtime (development mode)

```bash
go run ./cmd/aegis-runtime \
  --agent orchestrator-alpha \
  --config configs/agents_manifest.json \
  --scopes configs/tool_scopes.json \
  --policies policies/ \
  --otlp localhost:4317 \
  --trust-bundle path/to/ca-bundle.pem \
  --operator-pubkey <hex-encoded-ed25519-public-key>
```

`--trust-bundle` and `--operator-pubkey` are optional but security-relevant: without `--trust-bundle`, `SPIFFEManager.ValidatePeer` fails closed for every peer certificate; without `--operator-pubkey`, escalated actions fail closed (denied) rather than being auto-approved. For local experimentation, `internal/execution/approval_test.go` and `internal/identity/spiffe_test.go` show how to generate an `ed25519` operator keypair and a self-signed test CA using only the Go standard library (`crypto/ed25519`, `crypto/x509`) — hex-encode the resulting public key for `--operator-pubkey`, and PEM-encode the CA certificate for `--trust-bundle`.

---

## Autonomy Tier Model

AegisSwarm assigns every agent a tier that controls which tools it can access. This mirrors the CSA Agentic Trust Framework's "Intern to Principal" maturity model.

| Tier | Role Analogy | Permitted Risk Level | Example Agent |
|------|-------------|---------------------|---------------|
| 1 | Intern | Read-only, low-risk tools | `data-writer-delta` |
| 2 | Associate | Read/write within workspace | `coder-agent-beta`, `compliance-agent-gamma` |
| 3 | Senior | External API calls, delegation | `orchestrator-alpha` |
| 4 | Principal | High-consequence ops (human gate required) | SOC incident responder |

---

## CSA Alignment

This implementation is aligned with:

- **CSA Agentic Trust Framework (ATF)**: Woodruff et al., February 2026  
  Five governance pillars: Identity, Behavior, Data Governance, Segmentation, Incident Response
- **CSA Cloud Controls Matrix v4.1**: Identity and Access Management domain
- **OWASP Top 10 for Agentic Applications**: Released December 10, 2025
- **NIST AI Risk Management Framework**: Agentic AI profile, Govern and Manage functions
- **SPIFFE/SPIRE** (CNCF): Workload identity standard

---

## Contributing

This is a research reference implementation. Issues and pull requests are welcome for:
- Additional OPA policy modules (data residency, EU AI Act article mappings)
- Production SPIRE integration examples
- Additional vulnerability simulation scenarios
- Embedding-based goal drift detection (replacing the keyword heuristic in `goal_verifier.go`)

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions and PR guidelines.

---

## License

Apache 2.0. See LICENSE file.

---

## Citation

If you use AegisSwarm-Core in your research or implementation work, please cite:

> Gentyala, S. (2026). *Securing the Swarm: Governance, Attack Surfaces, and Zero-Trust Architectures in Multi-Agent AI Environments*. Cloud Security Alliance. https://cloudsecurityalliance.org/blog/2026/06/24/securing-the-swarm-governance-attack-surfaces-and-zero-trust-architectures-in-multi-agent-ai-environments
>
> Reference implementation: https://github.com/sunilgentyala/AegisSwarm-Core
>
> Author: https://github.com/sunilgentyala

---

## Media Coverage & Podcast Citations

- **LinkedIn — Asaf Nakash, ["AI Agent Held a Database for Ransom..."](https://www.linkedin.com/pulse/ai-agent-held-database-ransom-key-never-saved-paying-wouldnt-nakash-vqkpf/)**: names AegisSwarm directly, both in the article text ("researcher SUNIL Gentyala, called 'AegisSwarm,' ... sketching out how to verify and contain coordinated multi-agent systems") and in the author's own comment ("whose AegisSwarm proposal (hosted by the Cloud Security Alliance) is one of the few serious attempts to contain coordinated multi-agent systems").
- **Spotify — ["Context Window: AI Security Podcast"](https://open.spotify.com/episode/1PpMTGsBxmBY4TRhpCIDJz), agentic-ransomware episode**: related coverage of the same multi-agent threat landscape discussed in the LinkedIn post above; does not name AegisSwarm directly.
