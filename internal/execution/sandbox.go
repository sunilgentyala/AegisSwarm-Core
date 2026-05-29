package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

const defaultSandboxTimeoutSeconds = 30

// RunInSandbox executes a tool call inside a restricted, time-bounded context.
// Shell execution and direct filesystem mutations are explicitly rejected here
// as a defense-in-depth layer beyond the OPA guardrail check.
func RunInSandbox(ctx context.Context, toolID string, params json.RawMessage) (interface{}, error) {
	sandboxCtx, cancel := context.WithTimeout(ctx, defaultSandboxTimeoutSeconds*time.Second)
	defer cancel()

	handler, ok := registeredTools[toolID]
	if !ok {
		return nil, fmt.Errorf("unregistered tool: %s — execution blocked", toolID)
	}

	resultCh := make(chan toolResult, 1)
	go func() {
		out, err := handler(sandboxCtx, params)
		resultCh <- toolResult{output: out, err: err}
	}()

	select {
	case r := <-resultCh:
		return r.output, r.err
	case <-sandboxCtx.Done():
		return nil, fmt.Errorf("tool %s exceeded sandbox timeout (%ds)", toolID, defaultSandboxTimeoutSeconds)
	}
}

type toolResult struct {
	output interface{}
	err    error
}

// toolHandler is the function signature for all registered tools.
type toolHandler func(ctx context.Context, params json.RawMessage) (interface{}, error)

// registeredTools is the explicit whitelist of safe, sandboxable tools.
// Adding execute_shell or delete_resource here is intentionally blocked.
var registeredTools = map[string]toolHandler{
	"read_file":       handleReadFile,
	"list_directory":  handleListDirectory,
	"query_audit_log": handleQueryAuditLog,
	"generate_report": handleGenerateReport,
	"run_tests":       handleRunTests,
}

func handleReadFile(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("read_file: invalid params: %w", err)
	}
	if p.Path == "" {
		return nil, fmt.Errorf("read_file: path is required")
	}
	// Intentionally restricted — only allow relative paths within the workspace
	if len(p.Path) > 0 && p.Path[0] == '/' {
		return nil, fmt.Errorf("read_file: absolute paths are not permitted in sandbox")
	}
	return map[string]string{"path": p.Path, "status": "sandbox_stub"}, nil
}

func handleListDirectory(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("list_directory: invalid params: %w", err)
	}
	return map[string]string{"path": p.Path, "status": "sandbox_stub"}, nil
}

func handleQueryAuditLog(ctx context.Context, params json.RawMessage) (interface{}, error) {
	return map[string]string{"status": "sandbox_stub"}, nil
}

func handleGenerateReport(ctx context.Context, params json.RawMessage) (interface{}, error) {
	return map[string]string{"status": "sandbox_stub"}, nil
}

func handleRunTests(ctx context.Context, params json.RawMessage) (interface{}, error) {
	return map[string]string{"status": "sandbox_stub"}, nil
}
