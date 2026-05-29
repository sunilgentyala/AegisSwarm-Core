package aegisswarm.guardrail

# AegisSwarm OPA Autonomy Tier Policy
# Maps agent autonomy tiers to allowed tool risk levels.
# Tier 1 = Intern (read-only, low-risk)
# Tier 2 = Associate (read/write within workspace)
# Tier 3 = Senior (external API calls, delegated orchestration)
# Tier 4 = Principal (high-consequence ops with human approval gate)

import future.keywords.in

default decision = {"allow": false, "reason": "default deny — no matching rule"}

# Tier 1 agents may only call low-risk tools
decision = {"allow": true, "reason": "tier-1 low-risk tool permitted"} {
    input.tier == 1
    input.tool_id in tier1_tools
}

# Tier 2 agents may call low- and medium-risk tools
decision = {"allow": true, "reason": "tier-2 medium-risk tool permitted"} {
    input.tier == 2
    input.tool_id in tier2_tools
}

# Tier 3 agents may call any non-blocked tool
decision = {"allow": true, "reason": "tier-3 tool permitted"} {
    input.tier == 3
    not blocked_tools[input.tool_id]
}

# Tier 4 agents (Principal) may call any tool but high-consequence ops
# must pass through the human-approval gate in the Conductor
decision = {"allow": true, "reason": "tier-4 principal action — conductor enforces human gate"} {
    input.tier == 4
    not globally_blocked_tools[input.tool_id]
}

# Globally blocked tools — never permitted regardless of tier
decision = {"allow": false, "reason": "tool is globally blocked by policy"} {
    globally_blocked_tools[input.tool_id]
}

tier1_tools := {
    "read_file",
    "list_directory",
    "query_audit_log",
}

tier2_tools := tier1_tools | {
    "write_file",
    "generate_report",
    "run_tests",
}

blocked_tools := globally_blocked_tools | {
    "external_transfer",
    "delete_resource",
}

globally_blocked_tools := {
    "execute_shell",
    "external_transfer",
}
