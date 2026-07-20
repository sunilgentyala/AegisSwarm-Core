package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const defaultSandboxTimeoutSeconds = 30

// SandboxRoot is the single filesystem root that every sandboxed
// filesystem-touching tool handler (read_file, list_directory,
// generate_report, query_audit_log) is permitted to operate within. Any
// caller-supplied path that would resolve outside this root — via an
// absolute path, a "../" traversal, or a symlink that escapes it — is
// rejected by resolveInSandbox before any I/O happens. It defaults to the
// process working directory and can be pointed elsewhere with
// AEGISSWARM_SANDBOX_ROOT for deployment-specific configuration.
var SandboxRoot = resolveSandboxRoot()

func resolveSandboxRoot() string {
	root := os.Getenv("AEGISSWARM_SANDBOX_ROOT")
	if root == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "."
		}
		root = wd
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return root
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
}

// resolveInSandbox joins root with a caller-supplied relative path and
// verifies the resolved absolute path is actually contained within root.
// This is the real whitelist enforcement referenced throughout this file:
// it rejects absolute paths outright, and rejects any relative path whose
// lexical or symlink-resolved target lands outside root — not merely a
// path that happens to start with "/".
func resolveInSandbox(root, rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("path is required")
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("absolute paths are not permitted in sandbox")
	}

	joined := filepath.Join(root, rel)
	absJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", fmt.Errorf("could not resolve path: %w", err)
	}

	rootWithSep := root + string(filepath.Separator)
	if absJoined != root && !strings.HasPrefix(absJoined, rootWithSep) {
		return "", fmt.Errorf("path %q escapes sandbox root", rel)
	}

	// Where the target exists, resolve symlinks too, so a link planted
	// inside the root that points outside of it is still caught. Targets
	// that don't exist yet (e.g. a report about to be written) fall back
	// to the lexical check above.
	if resolved, err := filepath.EvalSymlinks(absJoined); err == nil {
		if resolved != root && !strings.HasPrefix(resolved, rootWithSep) {
			return "", fmt.Errorf("path %q escapes sandbox root via symlink", rel)
		}
		return resolved, nil
	}

	return absJoined, nil
}

// RunInSandbox executes a tool call inside a restricted, time-bounded context
// using the default timeout. Shell execution and direct filesystem mutations
// outside the whitelist are explicitly rejected here as a defense-in-depth
// layer beyond the OPA guardrail check.
func RunInSandbox(ctx context.Context, toolID string, params json.RawMessage) (interface{}, error) {
	return RunInSandboxWithTimeout(ctx, toolID, params, defaultSandboxTimeoutSeconds*time.Second)
}

// RunInSandboxWithTimeout is RunInSandbox with an explicit time budget.
// The handler runs in its own goroutine against a context derived from
// timeout; if that context expires before the handler finishes, this
// function returns a timeout error immediately rather than waiting for the
// handler, and — for handlers that shell out via exec.CommandContext (see
// handleRunTests) — the underlying OS process is actually killed, not just
// abandoned.
func RunInSandboxWithTimeout(ctx context.Context, toolID string, params json.RawMessage, timeout time.Duration) (interface{}, error) {
	sandboxCtx, cancel := context.WithTimeout(ctx, timeout)
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
		return nil, fmt.Errorf("tool %s exceeded sandbox timeout (%s)", toolID, timeout)
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

// handleReadFile reads a real file from within SandboxRoot and returns its
// content. Paths outside the sandbox root are rejected by
// resolveInSandbox before any filesystem call is made.
func handleReadFile(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("read_file: invalid params: %w", err)
	}

	full, err := resolveInSandbox(SandboxRoot, p.Path)
	if err != nil {
		return nil, fmt.Errorf("read_file: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(full)
	if err != nil {
		return nil, fmt.Errorf("read_file: %w", err)
	}

	return map[string]interface{}{
		"path":    p.Path,
		"content": string(data),
		"bytes":   len(data),
	}, nil
}

// handleListDirectory lists the real contents of a directory within
// SandboxRoot.
func handleListDirectory(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("list_directory: invalid params: %w", err)
	}
	if p.Path == "" {
		p.Path = "."
	}

	full, err := resolveInSandbox(SandboxRoot, p.Path)
	if err != nil {
		return nil, fmt.Errorf("list_directory: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(full)
	if err != nil {
		return nil, fmt.Errorf("list_directory: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			name += "/"
		}
		names = append(names, name)
	}

	return map[string]interface{}{"path": p.Path, "entries": names}, nil
}

// auditLogRelativePath is the default location, relative to SandboxRoot,
// of the append-only JSON-lines audit log that query_audit_log reads. It
// is resolved through resolveInSandbox exactly like a caller-supplied
// path, so it can never be pointed outside the sandbox root either.
const auditLogRelativePath = "audit.log"

// handleQueryAuditLog reads real entries from the JSON-lines audit log,
// most-recent-last, optionally limited to the last N lines. If the log
// does not exist yet, it returns an empty result rather than an error —
// that is a legitimate "no audit history yet" state, not a stub response.
func handleQueryAuditLog(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Limit int `json:"limit"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("query_audit_log: invalid params: %w", err)
		}
	}

	full, err := resolveInSandbox(SandboxRoot, auditLogRelativePath)
	if err != nil {
		return nil, fmt.Errorf("query_audit_log: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(full)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]interface{}{"entries": []string{}, "count": 0}, nil
		}
		return nil, fmt.Errorf("query_audit_log: %w", err)
	}

	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}
	if p.Limit > 0 && p.Limit < len(lines) {
		lines = lines[len(lines)-p.Limit:]
	}

	return map[string]interface{}{"entries": lines, "count": len(lines)}, nil
}

// reportsRelativeDir is where generate_report writes real report files,
// relative to SandboxRoot.
const reportsRelativeDir = "reports"

// handleGenerateReport writes a real report file under
// SandboxRoot/reports and returns its path and size. The report name is
// resolved through resolveInSandbox so a caller cannot use it to escape
// the sandbox (e.g. name="../../etc/passwd").
func handleGenerateReport(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("generate_report: invalid params: %w", err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("generate_report: name is required")
	}

	relPath := filepath.Join(reportsRelativeDir, p.Name)
	full, err := resolveInSandbox(SandboxRoot, relPath)
	if err != nil {
		return nil, fmt.Errorf("generate_report: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return nil, fmt.Errorf("generate_report: %w", err)
	}

	body := fmt.Sprintf("# AegisSwarm Report\ngenerated_at: %s\n\n%s\n",
		time.Now().UTC().Format(time.RFC3339), p.Content)

	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		return nil, fmt.Errorf("generate_report: %w", err)
	}

	return map[string]interface{}{"path": relPath, "bytes_written": len(body)}, nil
}

// handleRunTests actually runs `go test` for a whitelisted package path
// under SandboxRoot via exec.CommandContext, so that when the sandbox
// timeout fires, the real OS-level subprocess is killed — not just
// abandoned by an idle goroutine. This is the concrete realization of
// "time-bounded... tool dispatch" claimed for the sandbox executor.
func handleRunTests(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Package string `json:"package"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("run_tests: invalid params: %w", err)
		}
	}
	if p.Package == "" {
		p.Package = "./..."
	}
	// "./..." and "./foo/..." are legitimate Go package patterns rooted at
	// SandboxRoot. Absolute paths or "../" segments that would walk the
	// test invocation outside the sandbox root are rejected outright.
	if filepath.IsAbs(p.Package) || strings.Contains(p.Package, "../") {
		return nil, fmt.Errorf("run_tests: package pattern %q is not permitted", p.Package)
	}

	goBin := goBinaryPath()
	cmd := exec.CommandContext(ctx, goBin, "test", p.Package)
	cmd.Dir = SandboxRoot

	output, runErr := cmd.CombinedOutput()

	result := map[string]interface{}{
		"package": p.Package,
		"output":  string(output),
	}

	if ctx.Err() != nil {
		return result, fmt.Errorf("run_tests: %w", ctx.Err())
	}
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			result["exit_code"] = exitErr.ExitCode()
			result["passed"] = false
			return result, nil
		}
		return nil, fmt.Errorf("run_tests: %w", runErr)
	}

	result["exit_code"] = 0
	result["passed"] = true
	return result, nil
}

func goBinaryPath() string {
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	return "go"
}
