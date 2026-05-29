package aegisswarm.guardrail

# AegisSwarm OPA Network Access Control Policy
# Controls which tools an agent may use to reach external network resources.
# Every outbound call must be explicitly declared in the tool scope manifest.

import future.keywords.in

# Deny any attempt to call an external endpoint not in the approved registry
deny_external_access {
    input.tool_id in external_tools
    not approved_external_destination(input)
}

# Deny tool calls that embed IP literals (potential SSRF vectors)
deny_external_access {
    contains(input.payload, "169.254.")  # AWS metadata endpoint
}

deny_external_access {
    contains(input.payload, "::1")       # IPv6 loopback
}

deny_external_access {
    contains(input.payload, "localhost")
}

approved_external_destination(req) {
    req.tool_id == "external_api_call"
    req.tier >= 3
}

external_tools := {
    "external_api_call",
    "external_transfer",
}
