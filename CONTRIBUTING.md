# Contributing to AegisSwarm-Core

Thanks for considering a contribution. AegisSwarm-Core is a reference implementation, not a toy, so contributions that make the guardrails more realistic or better tested are the most valuable thing you can send.

---

## Getting Set Up

```bash
git clone https://github.com/sunilgentyala/AegisSwarm-Core.git
cd AegisSwarm-Core
go mod download
```

You'll also want:
- [SPIRE](https://spiffe.io/docs/latest/spire-about/spire-concepts/) running locally if you're touching `internal/identity/`
- [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa) if you're touching `policies/`

Run the test suite before and after your change:

```bash
go test ./tests/... -v
go test ./tests/vulnerability_simulation/... -v
opa check policies/
opa test policies/ -v
```

---

## Where to Start

Check the [issues](https://github.com/sunilgentyala/AegisSwarm-Core/issues) labeled `good first issue` or `help wanted`. If nothing there fits, these areas are always open:

- **New OPA policy modules** — data residency rules, EU AI Act article mappings, industry-specific autonomy tiers
- **Additional vulnerability simulation scenarios** in `tests/vulnerability_simulation/` — new prompt injection variants, tool-chaining exploits, ASI04/ASI05 coverage
- **Production SPIRE integration examples** — real deployment configs beyond the local dev setup
- **Replacing the keyword heuristic in `goal_verifier.go`** with embedding-based semantic drift detection
- **Prometheus/Grafana dashboard configs** for the metrics already emitted in `internal/telemetry/metrics.go`

---

## What Makes a Good PR

- One subsystem or policy module per PR
- New guardrail behavior ships with a test in `tests/` or `tests/vulnerability_simulation/`
- New Rego policies pass `opa check` and include a corresponding `opa test` case
- Reference the specific OWASP Agentic Top 10 ID (ASI01-ASI05) or CSA ATF pillar your change addresses, if applicable
- `go vet ./...` and `gofmt -l .` come back clean

---

## What Not to Send

- Changes that weaken a default (e.g., disabling mTLS by default, widening the globally-blocked tool list) without a documented threat-model justification
- Large refactors without a prior issue discussion
- Vendor-specific integrations that only work with one cloud provider, unless clearly labeled as an example under a new `examples/` path

---

## Questions

Open an issue. This is a research reference implementation maintained alongside a published CSA article, so response time is typically within a few days.
