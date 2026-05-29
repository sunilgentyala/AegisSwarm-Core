package telemetry

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// ToolCallsTotal counts every tool invocation by agent, tool, and decision.
	ToolCallsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "aegisswarm",
		Name:      "tool_calls_total",
		Help:      "Total tool invocations segmented by agent, tool, and decision.",
	}, []string{"agent_id", "tool_id", "decision"})

	// RiskScoreHistogram records the distribution of computed Rs values.
	RiskScoreHistogram = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "aegisswarm",
		Name:      "risk_score_histogram",
		Help:      "Distribution of the Rs = C_impact * (1 - P_conf) risk metric.",
		Buckets:   []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
	}, []string{"agent_id", "tool_id"})

	// EscalationTotal tracks the number of human-in-the-loop escalations.
	EscalationTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "aegisswarm",
		Name:      "escalation_total",
		Help:      "Count of tool calls that triggered human escalation.",
	}, []string{"agent_id"})

	// InjectionDetectionsTotal counts prompt injection detections by stage.
	InjectionDetectionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "aegisswarm",
		Name:      "injection_detections_total",
		Help:      "Count of prompt injection detections by stage (regex|opa).",
	}, []string{"agent_id", "stage"})

	// TokenBudgetRemaining tracks per-agent remaining token budget as a gauge.
	TokenBudgetRemaining = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "aegisswarm",
		Name:      "token_budget_remaining",
		Help:      "Remaining token budget for each active agent session.",
	}, []string{"agent_id", "session_id"})

	// SessionsActive tracks the count of currently active agent sessions.
	SessionsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "aegisswarm",
		Name:      "sessions_active",
		Help:      "Number of currently active agent execution sessions.",
	})
)

// ServeMetrics starts a Prometheus /metrics endpoint on addr (e.g., ":9090").
func ServeMetrics(addr string) {
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(addr, nil) //nolint:errcheck
}
