package server

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
)

// Claude Code is an interactive terminal application. A PTY keeps its
// readline/UI behaviour intact while allowing the Web UI to relay input and
// stream output. The session deliberately lives outside the Python scanner:
// static analysis remains a bounded subprocess and the user owns the external
// agent's trust boundary.

const (
	claudeStatusPrepared = "prepared"
	claudeStatusStarting = "starting"
	claudeStatusRunning  = "running"
	claudeStatusDone     = "done"
	claudeStatusStopped  = "stopped"
	claudeStatusBlocked  = "blocked"
	claudeStatusError    = "error"
	maxClaudeEvents      = 12000
	maxClaudeEventBytes  = 16 << 20
)

// claudeTaskInfo is the stable hand-off metadata returned to the browser after
// OpenAnt has prepared the task package.
type claudeTaskInfo struct {
	Mode              string `json:"mode"`
	TaskWorkspace     string `json:"task_workspace"`
	PublicToolLibrary string `json:"public_tool_library"`
	TaskManifestPath  string `json:"task_manifest_path"`
	CandidateManifest string `json:"candidate_manifest,omitempty"`
	LaunchCommand     string `json:"launch_command"`
	CandidateCount    int    `json:"candidate_count"`
}

type claudeEvent struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"created_at"`
}

type claudeSession struct {
	mu           sync.Mutex
	taskDir      string
	status       string
	exitCode     int
	events       []claudeEvent
	eventBytes   int
	eventsCapped bool
	nextID       int64

	cmd    *exec.Cmd
	pty    *os.File
	cancel context.CancelFunc
	done   chan struct{}
}

func newClaudeSession(taskDir string) *claudeSession {
	return &claudeSession{
		taskDir: taskDir,
		status:  claudeStatusPrepared,
		done:    make(chan struct{}),
	}
}

func (s *claudeSession) appendEvent(kind, text string) {
	text = cleanClaudeOutput(text)
	if text == "" && kind == "output" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) >= maxClaudeEvents || s.eventBytes+len(text) > maxClaudeEventBytes {
		if !s.eventsCapped {
			s.events = append(s.events, claudeEvent{
				ID:        s.nextID,
				Kind:      "system",
				Text:      "Claude 会话输出已达到保存上限，后续输出不再缓存。",
				CreatedAt: time.Now().UTC(),
			})
			s.nextID++
			s.eventsCapped = true
		}
		return
	}
	s.events = append(s.events, claudeEvent{
		ID:        s.nextID,
		Kind:      kind,
		Text:      text,
		CreatedAt: time.Now().UTC(),
	})
	s.nextID++
	s.eventBytes += len(text)
}

func (s *claudeSession) snapshot() (string, int, []claudeEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	events := make([]claudeEvent, len(s.events))
	copy(events, s.events)
	return s.status, s.exitCode, events
}

func (s *claudeSession) eventsAfter(lastID int64) []claudeEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if lastID < -1 {
		lastID = -1
	}
	start := 0
	for start < len(s.events) && s.events[start].ID <= lastID {
		start++
	}
	events := make([]claudeEvent, len(s.events)-start)
	copy(events, s.events[start:])
	return events
}

func (s *claudeSession) start(parent context.Context, onLog func(string)) error {
	claudePath := strings.TrimSpace(os.Getenv("OPENANT_CLAUDE_BIN"))
	if claudePath == "" {
		var err error
		claudePath, err = exec.LookPath("claude")
		if err != nil {
			s.mu.Lock()
			s.status = claudeStatusBlocked
			s.mu.Unlock()
			s.appendEvent("system", "未找到 claude 命令。请安装 Claude Code，或设置 OPENANT_CLAUDE_BIN。")
			close(s.done)
			return fmt.Errorf("claude executable not found: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(parent)
	cmd := exec.CommandContext(ctx, claudePath, "--dangerously-skip-permissions")
	cmd.Dir = s.taskDir
	cmd.Env = os.Environ()

	s.mu.Lock()
	s.status = claudeStatusStarting
	s.cmd = cmd
	s.cancel = cancel
	s.mu.Unlock()
	s.appendEvent("system", "正在启动 Claude Code（任务目录："+s.taskDir+"）…")

	terminal, err := pty.Start(cmd)
	if err != nil {
		cancel()
		s.mu.Lock()
		s.status = claudeStatusError
		s.mu.Unlock()
		s.appendEvent("error", "Claude Code 启动失败："+err.Error())
		close(s.done)
		return fmt.Errorf("start claude: %w", err)
	}
	// Claude Code renders an interactive Ink UI. A larger initial terminal
	// prevents narrow default PTY dimensions from collapsing labels and
	// wrapping the prompt into unreadable fragments in the Web transcript.
	_ = pty.Setsize(terminal, &pty.Winsize{Cols: 160, Rows: 48})

	s.mu.Lock()
	s.pty = terminal
	s.status = claudeStatusRunning
	s.mu.Unlock()
	s.appendEvent("system", "Claude Code 已连接。可以在下方输入消息。")
	if onLog != nil {
		onLog("[dynamic-test] Claude Code session started")
	}

	go func() {
		readDone := make(chan struct{})
		// Closing the PTY on context cancellation unblocks Read even when the
		// child has not yet reacted to CommandContext's kill request.
		go func() {
			select {
			case <-ctx.Done():
				s.mu.Lock()
				terminal := s.pty
				s.mu.Unlock()
				if terminal != nil {
					_ = terminal.Close()
				}
			case <-readDone:
			}
		}()

		buffer := make([]byte, 4096)
		for {
			n, readErr := terminal.Read(buffer)
			if n > 0 {
				text := cleanClaudeOutput(string(buffer[:n]))
				if text != "" {
					s.appendEvent("output", text)
					if onLog != nil {
						onLog("[claude] " + compactClaudeLog(text))
					}
				}
			}
			if readErr != nil {
				break
			}
		}
		_ = terminal.Close()
		close(readDone)
		waitErr := cmd.Wait()

		s.mu.Lock()
		s.exitCode = 0
		if cmd.ProcessState != nil {
			s.exitCode = cmd.ProcessState.ExitCode()
		}
		wasStopped := ctx.Err() != nil || s.status == claudeStatusStopped
		s.pty = nil
		if wasStopped {
			s.status = claudeStatusStopped
		} else if waitErr != nil {
			s.status = claudeStatusError
		} else {
			s.status = claudeStatusDone
		}
		status := s.status
		exitCode := s.exitCode
		s.mu.Unlock()
		// Stop the context watcher after a natural exit; otherwise it would
		// remain blocked until the whole scan is cancelled.
		cancel()

		if status == claudeStatusDone {
			s.appendEvent("system", "Claude Code 已结束。")
		} else if status == claudeStatusStopped {
			s.appendEvent("system", "Claude Code 会话已停止。")
		} else {
			s.appendEvent("error", fmt.Sprintf("Claude Code 退出（状态码 %d）。", exitCode))
		}
		close(s.done)
	}()
	return nil
}

func (s *claudeSession) writeMessage(message string) error {
	message = strings.TrimSpace(message)
	if message == "" {
		return fmt.Errorf("message is empty")
	}
	s.mu.Lock()
	terminal := s.pty
	status := s.status
	s.mu.Unlock()
	if status != claudeStatusRunning || terminal == nil {
		return fmt.Errorf("Claude Code is not running")
	}
	// Raw terminal applications treat carriage return as the Enter key. LF is
	// echoed as text by Claude Code's input layer, leaving the question in the
	// prompt without submitting it (the session then appears idle forever).
	if _, err := terminal.Write([]byte(message + "\r")); err != nil {
		return fmt.Errorf("write Claude Code input: %w", err)
	}
	s.appendEvent("input", message)
	return nil
}

func (s *claudeSession) stop() {
	s.mu.Lock()
	if s.status != claudeStatusRunning && s.status != claudeStatusStarting {
		s.mu.Unlock()
		return
	}
	s.status = claudeStatusStopped
	cancel := s.cancel
	terminal := s.pty
	s.mu.Unlock()
	s.appendEvent("system", "正在停止 Claude Code…")
	if cancel != nil {
		cancel()
	}
	if terminal != nil {
		_ = terminal.Close()
	}
}

func (s *claudeSession) wait() { <-s.done }

var claudeANSI = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))`)

func cleanClaudeOutput(value string) string {
	value = claudeANSI.ReplaceAllString(value, "")
	value = strings.ReplaceAll(value, "\x1b", "")
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r == '\n' || r == '\t':
			builder.WriteRune(r)
		case r == '\r':
			builder.WriteRune('\n')
		case r >= 0x20 && r != 0x7f:
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func compactClaudeLog(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 1200 {
		return value[:1200] + "…"
	}
	return value
}
