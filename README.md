# AegisSwarm-Core

**Zero-Trust Security and Governance Reference Architecture for Autonomous Multi-Agent AI Systems**

Author: Sunil Gentyala | HCLTECH (HCL America Inc.) | sunil.gentyala@ieee.org  
Framework Version: 1.0.0  
CSA Agentic Trust Framework Aligned | OWASP Top 10 Risks and Mitigations for Agentic AI Security (Dec 2025) | NIST AI RMF 1.0

> **Paper submitted to the Cloud Security Alliance (CSA) Research Program.**  
> Accompanying whitepaper: *"Securing the Swarm: Governance, Attack Surfaces, and Zero-Trust Architectures in Multi-Agent AI Environments"* — Sunil Gentyala, May 2026.

---

## Overview

AegisSwarm-Core is the open-source reference implementation accompanying the CSA whitepaper *"Securing the Swarm: Governance, Attack Surfaces, and Zero-Trust Architectures in Multi-Agent AI Environments"* (May 2026).

Enterprise AI has moved beyond isolated LLM prompts into autonomous Multi-Agent Systems (MAS) where specialized digital workers decompose, delegate, and execute tasks without per-step human oversight. While this unlocks dramatic operational velocity, it introduces execution-plane attack surfaces that legacy perimeter defenses cannot address.

AegisSwarm wraps a strict, deterministic boundary layer around autonomous agent networks. Rather than modifying model weights or relying on alignment alone, it intercepts, evaluates, and audits every agentic action in real time using four independent subsystems.

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

### 3. OPA Guard Control
Before any tool executes, the structured request payload is evaluated against Rego policies in [Open Policy Agent](https://www.openpolicyagent.org/). Policies enforce autonomy tiers, globally blocked tools (`execute_shell`, `external_transfer`), and network access controls.

### 4. Escalation and Human-in-the-Loop Runtime
AegisSwarm computes a dynamic risk score for every proposed transaction:

```
Rs = C_impact × (1 − P_conf)
```

Where `C_impact` is the configured critical cost of the target resource and `P_conf` is the agent's internal confidence score. If `Rs` exceeds the agent's configured threshold, execution freezes until an authenticated human operator provides cryptographic clearance.

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
- [SPIRE](https://spiffe.io/docs/latest/spire-about/spire-concepts/) agent running locally
- [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa) (for policy development)
- OpenTelemetry collector (optional, for trace export)

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
  --otlp localhost:4317
```

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

- **CSA Agentic Trust Framework (ATF)** — Woodruff et al., February 2026  
  Five governance pillars: Identity, Behavior, Data Governance, Segmentation, Incident Response
- **CSA Cloud Controls Matrix v4.1** — Identity and Access Management domain
- **OWASP Top 10 for Agentic Applications** — Released December 10, 2025
- **NIST AI Risk Management Framework** — Agentic AI profile, Govern and Manage functions
- **SPIFFE/SPIRE** (CNCF) — Workload identity standard

---

## Contributing

This is a research reference implementation. Issues and pull requests are welcome for:
- Additional OPA policy modules (data residency, EU AI Act article mappings)
- Production SPIRE integration examples
- Additional vulnerability simulation scenarios
- Embedding-based goal drift detection (replacing the keyword heuristic in `goal_verifier.go`)

---

## License

Apache 2.0 — See LICENSE file.

---

## Citation

If you use AegisSwarm-Core in your research or implementation work, please cite:

> Gentyala, S. (2026). *Securing the Swarm: Governance, Attack Surfaces, and Zero-Trust Architectures in Multi-Agent AI Environments*. Cloud Security Alliance. https://github.com/sunilgentyala/AegisSwarm-Core
