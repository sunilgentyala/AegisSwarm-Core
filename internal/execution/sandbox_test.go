package execution

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withSandboxRoot points SandboxRoot at a temp directory for the duration
// of a test and restores the previous value afterwards.
func withSandboxRoot(t *testing.T, dir string) {
	t.Helper()
	prev := SandboxRoot
	SandboxRoot = dir
	t.Cleanup(func() { SandboxRoot = prev })
}

// TestHandleReadFile_WhitelistedReadSucceeds proves handleReadFile does
// real filesystem I/O (not the old "sandbox_stub" placeholder): a file
// written inside the sandbox root is read back with its actual content.
func TestHandleReadFile_WhitelistedReadSucceeds(t *testing.T) {
	dir := t.TempDir()
	withSandboxRoot(t, dir)

	want := "real-content-not-a-stub-12345"
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte(want), 0o644); err != nil {
		t.Fatalf("setup write: %v", err)
	}

	params, _ := json.Marshal(map[string]string{"path": "hello.txt"})
	out, err := handleReadFile(context.Background(), params)
	if err != nil {
		t.Fatalf("handleReadFile: %v", err)
	}

	m, ok := out.(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected result type %T", out)
	}
	if m["content"] != want {
		t.Fatalf("expected real file content %q, got %q (stub behavior would return no content at all)", want, m["content"])
	}
}

// TestHandleReadFile_PathTraversalRejected proves the whitelist is
// actually enforced: both an absolute path and a "../" traversal that
// would escape the sandbox root are rejected before any file is read, and
// the real secret file outside the root is never disclosed.
func TestHandleReadFile_PathTraversalRejected(t *testing.T) {
	root := t.TempDir()
	outsideDir := t.TempDir()
	withSandboxRoot(t, root)

	secret := "TOP-SECRET-OUTSIDE-SANDBOX"
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte(secret), 0o644); err != nil {
		t.Fatalf("setup write: %v", err)
	}

	// Attempt 1: absolute path escape.
	paramsAbs, _ := json.Marshal(map[string]string{"path": outsideFile})
	if out, err := handleReadFile(context.Background(), paramsAbs); err == nil {
		t.Fatalf("SECURITY FAILURE: absolute path escape was not rejected, got result: %v", out)
	}

	// Attempt 2: relative traversal escape ("../").
	rel, err := filepath.Rel(root, outsideFile)
	if err != nil {
		t.Fatalf("computing relative traversal path: %v", err)
	}
	paramsRel, _ := json.Marshal(map[string]string{"path": rel})
	out, err := handleReadFile(context.Background(), paramsRel)
	if err == nil {
		t.Fatalf("SECURITY FAILURE: relative '../' traversal escape was not rejected, got result: %v", out)
	}
	if m, ok := out.(map[string]interface{}); ok {
		if content, ok := m["content"].(string); ok && content == secret {
			t.Fatal("SECURITY FAILURE: secret file content outside sandbox root was disclosed")
		}
	}
}

// TestHandleListDirectory_Real proves list_directory returns real
// directory entries rather than a stub placeholder.
func TestHandleListDirectory_Real(t *testing.T) {
	dir := t.TempDir()
	withSandboxRoot(t, dir)

	for _, name := range []string{"a.txt", "b.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}

	params, _ := json.Marshal(map[string]string{"path": "."})
	out, err := handleListDirectory(context.Background(), params)
	if err != nil {
		t.Fatalf("handleListDirectory: %v", err)
	}
	m := out.(map[string]interface{})
	entries := m["entries"].([]string)
	if len(entries) != 3 {
		t.Fatalf("expected 3 real directory entries, got %d: %v", len(entries), entries)
	}
}

// TestHandleGenerateReport_WritesRealFile proves generate_report performs
// a real, verifiable filesystem write instead of returning a stub status.
func TestHandleGenerateReport_WritesRealFile(t *testing.T) {
	dir := t.TempDir()
	withSandboxRoot(t, dir)

	params, _ := json.Marshal(map[string]string{"name": "compliance.md", "content": "audit passed"})
	out, err := handleGenerateReport(context.Background(), params)
	if err != nil {
		t.Fatalf("handleGenerateReport: %v", err)
	}
	m := out.(map[string]interface{})
	writtenPath := filepath.Join(dir, m["path"].(string))

	data, err := os.ReadFile(writtenPath)
	if err != nil {
		t.Fatalf("expected report file to actually exist on disk: %v", err)
	}
	if !strings.Contains(string(data), "audit passed") {
		t.Fatalf("report file did not contain expected content, got: %s", data)
	}
}

// TestHandleQueryAuditLog_ReadsRealEntries proves query_audit_log reads
// real log lines from disk rather than returning a stub status.
func TestHandleQueryAuditLog_ReadsRealEntries(t *testing.T) {
	dir := t.TempDir()
	withSandboxRoot(t, dir)

	logContent := "line-one\nline-two\nline-three\n"
	if err := os.WriteFile(filepath.Join(dir, auditLogRelativePath), []byte(logContent), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	params, _ := json.Marshal(map[string]int{"limit": 2})
	out, err := handleQueryAuditLog(context.Background(), params)
	if err != nil {
		t.Fatalf("handleQueryAuditLog: %v", err)
	}
	m := out.(map[string]interface{})
	entries := m["entries"].([]string)
	if len(entries) != 2 || entries[0] != "line-two" || entries[1] != "line-three" {
		t.Fatalf("expected real last-2 log entries [line-two line-three], got %v", entries)
	}
}

// TestRunInSandboxWithTimeout_CancelsSlowHandler proves the sandbox
// executor actually enforces its time budget: a handler that would take
// far longer than its allotted timeout is cut off, and RunInSandboxWithTimeout
// returns promptly with a timeout error rather than waiting for the
// handler to finish.
func TestRunInSandboxWithTimeout_CancelsSlowHandler(t *testing.T) {
	const toolID = "test_slow_probe"
	finished := make(chan struct{})

	registeredTools[toolID] = func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		select {
		case <-time.After(3 * time.Second):
			close(finished) // would only happen if NOT actually cancelled in time
			return "should not get here", nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	t.Cleanup(func() { delete(registeredTools, toolID) })

	start := time.Now()
	_, err := RunInSandboxWithTimeout(context.Background(), toolID, json.RawMessage(`{}`), 150*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error from a handler exceeding its time budget")
	}
	if elapsed > time.Second {
		t.Fatalf("RunInSandboxWithTimeout took %v to return; the 150ms budget was not actually enforced", elapsed)
	}

	select {
	case <-finished:
		t.Fatal("SECURITY FAILURE: the slow handler was allowed to run to completion past its time budget")
	case <-time.After(50 * time.Millisecond):
		// expected: handler's own ctx.Done() branch fired well before its 3s sleep would have.
	}
}

// TestRunInSandboxWithTimeout_UnregisteredToolRejected proves the
// whitelist at the RunInSandbox layer still rejects unregistered tools
// (e.g. execute_shell was never added to registeredTools).
func TestRunInSandboxWithTimeout_UnregisteredToolRejected(t *testing.T) {
	_, err := RunInSandboxWithTimeout(context.Background(), "execute_shell", json.RawMessage(`{}`), time.Second)
	if err == nil {
		t.Fatal("SECURITY FAILURE: an unregistered/non-whitelisted tool was executed")
	}
}

// TestHandleRunTests_ExecutesRealGoTest proves run_tests genuinely spawns
// `go test` against a real, temporary Go module and reports its real
// pass/fail result, instead of returning the old "sandbox_stub" status
// with no execution at all.
func TestHandleRunTests_ExecutesRealGoTest(t *testing.T) {
	dir := t.TempDir()
	withSandboxRoot(t, dir)
	writeTempGoModule(t, dir, `package sample

import "testing"

func TestAlwaysPasses(t *testing.T) {}
`)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	out, err := handleRunTests(ctx, json.RawMessage(`{"package":"./..."}`))
	if err != nil {
		t.Fatalf("handleRunTests: %v", err)
	}
	m := out.(map[string]interface{})
	if passed, _ := m["passed"].(bool); !passed {
		t.Fatalf("expected the real `go test` run to pass, got result: %+v", m)
	}
	output, _ := m["output"].(string)
	if !strings.Contains(output, "PASS") && !strings.Contains(output, "ok") {
		t.Fatalf("expected real `go test` output containing PASS/ok, got: %s", output)
	}
}

// TestHandleRunTests_RealCancellation proves that when run_tests is given
// less time than the real `go test` subprocess needs, the OS-level process
// is actually killed by exec.CommandContext — not merely abandoned by an
// idle goroutine while it keeps running in the background.
func TestHandleRunTests_RealCancellation(t *testing.T) {
	dir := t.TempDir()
	withSandboxRoot(t, dir)
	writeTempGoModule(t, dir, `package sample

import (
	"testing"
	"time"
)

func TestSleepsTooLong(t *testing.T) {
	time.Sleep(5 * time.Second)
}
`)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := handleRunTests(ctx, json.RawMessage(`{"package":"./..."}`))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected run_tests to report an error when the real go test process was cancelled")
	}
	// The underlying test sleeps for 5s; if the subprocess were not truly
	// killed, this call would take at least that long.
	if elapsed > 4*time.Second {
		t.Fatalf("handleRunTests took %v; the go test subprocess does not appear to have been actually killed on cancellation", elapsed)
	}
}

// writeTempGoModule creates a minimal, dependency-free Go module in dir
// containing the given test file content, so handleRunTests has something
// real to execute.
func writeTempGoModule(t *testing.T, dir, testFileContent string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module sandboxtestfixture\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatalf("writing go.mod fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sample_test.go"), []byte(testFileContent), 0o644); err != nil {
		t.Fatalf("writing test fixture: %v", err)
	}
}
