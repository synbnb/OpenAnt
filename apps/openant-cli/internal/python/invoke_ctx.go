package python

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/knostic/open-ant-cli/internal/types"
)

const maxInvokeStderrTail = 8 * 1024

// lineWriter forwards complete stderr lines to onLog as they arrive. Used as
// cmd.Stderr (a managed io.Writer) instead of a StderrPipe scanner so os/exec
// owns the copy goroutine and WaitDelay can force-close a pipe a detached child
// still holds. A single partial line is capped so a repo can't exhaust memory.
type lineWriter struct {
	onLog func(string)
	buf   []byte
	tail  []byte
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			if len(w.buf) > 1024*1024 { // flush a pathologically long partial line
				w.emit(w.buf)
				w.buf = w.buf[:0]
			}
			break
		}
		w.emit(w.buf[:i])
		w.buf = w.buf[i+1:]
	}
	return len(p), nil
}

func (w *lineWriter) emit(line []byte) {
	if w.onLog != nil {
		w.onLog(string(line))
	}
	// Keep a small diagnostic tail even when the caller does not subscribe to
	// live logs.  Source-locator requests historically passed onLog=nil, so a
	// killed Python worker left only the misleading JSON EOF error visible to
	// the Web UI.
	w.tail = append(w.tail, line...)
	w.tail = append(w.tail, '\n')
	if len(w.tail) > maxInvokeStderrTail {
		w.tail = w.tail[len(w.tail)-maxInvokeStderrTail:]
	}
}

// flush emits any buffered trailing line with no newline. Call after cmd.Wait,
// which guarantees the copy goroutine has finished (no concurrent Write).
func (w *lineWriter) flush() {
	if len(w.buf) > 0 {
		w.emit(w.buf)
		w.buf = w.buf[:0]
	}
}

func emptyCaptureError(ctx context.Context, exitCode int, stderrTail string) error {
	detail := fmt.Sprintf("Python worker produced no JSON envelope (exit code %d)", exitCode)
	if ctxErr := ctx.Err(); ctxErr != nil {
		detail += "; context: " + ctxErr.Error()
	}
	if stderrTail = strings.TrimSpace(stderrTail); stderrTail != "" {
		detail += "; stderr tail: " + stderrTail
	}
	return errors.New(detail)
}

// InvokeCtx runs `python -m openant <args>` with context-cancellation support.
// Each stderr line is passed to onLog in real time.  stdout is discarded.
// On context cancellation, SIGKILL is sent to the entire process group so all
// child processes (e.g. parallel workers) are killed.
// Returns the exit code and any error (cancelled runs return exit code -1, nil).
func InvokeCtx(ctx context.Context, pythonPath string, args []string, workDir, apiKey string, onLog func(string)) (int, error) {
	_, code, err := invokeCtxInner(ctx, pythonPath, args, workDir, apiKey, onLog, false)
	return code, err
}

// InvokeCtxCapture runs `python -m openant <args>` like InvokeCtx but also
// captures and returns the full stdout content (e.g. JSON output).
func InvokeCtxCapture(ctx context.Context, pythonPath string, args []string, workDir, apiKey string, onLog func(string)) (stdout string, exitCode int, err error) {
	return invokeCtxInner(ctx, pythonPath, args, workDir, apiKey, onLog, true)
}

// DecodeEnvelope strictly decodes the single JSON document emitted by the
// Python CLI.  Source-locator workers use this helper instead of accepting
// arbitrary stdout: progress belongs on stderr, and trailing JSON/text would
// otherwise make a Web session appear successful while silently dropping data.
func DecodeEnvelope(raw string) (types.Envelope, error) {
	var envelope types.Envelope
	decoder := json.NewDecoder(strings.NewReader(strings.TrimSpace(raw)))
	if err := decoder.Decode(&envelope); err != nil {
		return types.Envelope{}, fmt.Errorf("decode Python JSON envelope: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return types.Envelope{}, errors.New("decode Python JSON envelope: multiple JSON documents")
		}
		return types.Envelope{}, fmt.Errorf("decode Python JSON envelope: trailing data: %w", err)
	}
	if envelope.Status != "success" && envelope.Status != "error" && envelope.Status != "interrupted" {
		return types.Envelope{}, fmt.Errorf("decode Python JSON envelope: unsupported status %q", envelope.Status)
	}
	if envelope.Errors == nil {
		envelope.Errors = []string{}
	}
	return envelope, nil
}

// InvokeSourceLocator invokes exactly one source-locator CLI operation and
// decodes its JSON envelope.  It deliberately does not expose a generic shell
// command: callers provide parsed argv tokens, while the Python command owns
// all filesystem/path validation.
func InvokeSourceLocator(ctx context.Context, pythonPath string, args []string, workDir string, onLog func(string)) (*InvokeResult, error) {
	commandArgs := append([]string{"source-locator"}, args...)
	stdout, exitCode, err := InvokeCtxCapture(ctx, pythonPath, commandArgs, workDir, "", onLog)
	if err != nil {
		return nil, err
	}
	envelope, err := DecodeEnvelope(stdout)
	if err != nil {
		return nil, err
	}
	return &InvokeResult{
		Envelope: envelope,
		ExitCode: normalizeExit(exitCode, envelope.Status == "error"),
	}, nil
}

// InvokeExposureSurface invokes exactly one standalone exposure-surface
// operation.  Keeping the command namespace explicit prevents the Web layer
// from turning this bridge into a generic Python or shell execution endpoint.
func InvokeExposureSurface(ctx context.Context, pythonPath string, args []string, workDir string, onLog func(string)) (*InvokeResult, error) {
	commandArgs := append([]string{"exposure-surface"}, args...)
	stdout, exitCode, err := InvokeCtxCapture(ctx, pythonPath, commandArgs, workDir, "", onLog)
	if err != nil {
		return nil, err
	}
	envelope, err := DecodeEnvelope(stdout)
	if err != nil {
		return nil, err
	}
	return &InvokeResult{
		Envelope: envelope,
		ExitCode: normalizeExit(exitCode, envelope.Status == "error"),
	}, nil
}

func invokeCtxInner(ctx context.Context, pythonPath string, args []string, workDir, apiKey string, onLog func(string), captureStdout bool) (string, int, error) {
	// -P keeps the process working directory off sys.path so a hostile openant/
	// package inside the scanned, untrusted repo can't shadow the real module on
	// import. The web UI is the untrusted-repo-scanning path, so it needs the same
	// guard the CLI's Invoke uses (see invoke.go); it also propagates to the report
	// subprocesses the engine spawns.
	cmdArgs := append([]string{"-P", "-m", "openant"}, args...)
	cmd := exec.CommandContext(ctx, pythonPath, cmdArgs...)

	if workDir != "" {
		cmd.Dir = workDir
	}
	cmd.Env = withConfigEnv(os.Environ())
	if apiKey != "" {
		cmd.Env = setEnv(cmd.Env, "ANTHROPIC_API_KEY", apiKey)
	}
	// New process group so we can kill all descendants at once (unix; no-op
	// elsewhere). os/exec drives cancellation: its watch goroutine calls Cancel
	// once and stops before Wait reaps the child, so there is no window to SIGKILL
	// a recycled pgid after reaping.
	setProcGroupKill(cmd)
	cmd.WaitDelay = 5 * time.Second

	var stdoutBuf bytes.Buffer
	if captureStdout {
		cmd.Stdout = &stdoutBuf
	} else {
		cmd.Stdout = io.Discard
	}
	// Managed line-writer for stderr instead of StderrPipe: os/exec runs the copy
	// goroutine, so WaitDelay can force-close the pipe if a killed OR a naturally
	// exited process leaves a detached child holding the write end. A StderrPipe
	// scanner read before Wait() would instead deadlock there — the read never
	// sees EOF, so Wait (which starts WaitDelay) is never reached.
	lw := &lineWriter{onLog: onLog}
	cmd.Stderr = lw

	if err := cmd.Start(); err != nil {
		return "", 0, fmt.Errorf("start: %w", err)
	}

	exitErr := cmd.Wait()
	lw.flush() // emit any trailing partial line; Wait has drained the copy goroutine

	exitCode := 0
	if exitErr != nil {
		if ee, ok := exitErr.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else if errors.Is(exitErr, exec.ErrWaitDelay) && cmd.ProcessState != nil {
			// The process itself exited but a lingering pipe holder tripped
			// WaitDelay; retain the real process exit code.
			exitCode = cmd.ProcessState.ExitCode()
		} else {
			if ctx.Err() != nil {
				return "", -1, fmt.Errorf("wait after Python worker cancellation: %w", ctx.Err())
			}
			return "", 0, fmt.Errorf("wait: %w", exitErr)
		}
	}
	if captureStdout && strings.TrimSpace(stdoutBuf.String()) == "" {
		return stdoutBuf.String(), exitCode, emptyCaptureError(ctx, exitCode, string(lw.tail))
	}
	return stdoutBuf.String(), exitCode, nil
}
