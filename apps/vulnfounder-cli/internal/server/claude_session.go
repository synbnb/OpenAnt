package server

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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
// VulnFounder has prepared the task package.
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
	// outputDecoder is owned by the PTY reader goroutine.  Keeping decoder
	// state across reads is important because ANSI escape sequences and UTF-8
	// code points can be split at any byte boundary by os.File.Read.
	outputDecoder claudeOutputDecoder

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
	claudePath := strings.TrimSpace(os.Getenv("VULNFOUNDER_CLAUDE_BIN"))
	if claudePath == "" {
		claudePath = strings.TrimSpace(os.Getenv("OPENANT_CLAUDE_BIN"))
	}
	if claudePath == "" {
		var err error
		claudePath, err = exec.LookPath("claude")
		if err != nil {
			s.mu.Lock()
			s.status = claudeStatusBlocked
			s.mu.Unlock()
			s.appendEvent("system", "未找到 claude 命令。请安装 Claude Code，或设置 VULNFOUNDER_CLAUDE_BIN（兼容 OPENANT_CLAUDE_BIN）。")
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
				text := s.outputDecoder.decode(buffer[:n])
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
		// Any unterminated escape sequence is intentionally discarded.  It is
		// terminal state, not user-visible text, and retaining it would leak a
		// fragment into the next browser replay.
		_ = s.outputDecoder.flush()
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

// claudeOutputDecoder converts PTY bytes into append-only, browser-safe text.
// Claude Code uses Ink and therefore emits ANSI cursor movement, screen-clear,
// colour and OSC sequences.  A regular expression is insufficient here: a
// read may end in the middle of an escape sequence (or UTF-8 character), and
// the next read must continue parsing from that exact boundary.
type claudeOutputDecoder struct {
	pending   []byte
	lastWasCR bool
}

func (d *claudeOutputDecoder) decode(input []byte) string {
	if len(input) == 0 && len(d.pending) == 0 {
		return ""
	}
	data := make([]byte, 0, len(d.pending)+len(input))
	data = append(data, d.pending...)
	data = append(data, input...)
	d.pending = nil

	out := make([]rune, 0, len(data))
	for i := 0; i < len(data); {
		if data[i] == 0x1b { // ESC
			consumed, complete := consumeClaudeEscape(data[i:])
			if !complete {
				d.pending = append(d.pending, data[i:]...)
				break
			}
			i += consumed
			continue
		}

		// C0 controls are terminal protocol, not text.  Keep tabs/newlines,
		// turn CR redraws into line breaks, and discard the remaining controls.
		switch data[i] {
		case '\r':
			out = append(out, '\n')
			d.lastWasCR = true
			i++
			continue
		case '\n':
			if !d.lastWasCR {
				out = append(out, '\n')
			}
			d.lastWasCR = false
			i++
			continue
		case '\t':
			out = append(out, '\t')
			d.lastWasCR = false
			i++
			continue
		case 0x08: // backspace is often used by spinners; do not expose it
			d.lastWasCR = false
			i++
			continue
		}
		if data[i] < 0x20 || data[i] == 0x7f || (data[i] >= 0x80 && data[i] <= 0x9f) {
			d.lastWasCR = false
			i++
			continue
		}

		if data[i] < utf8.RuneSelf {
			out = append(out, rune(data[i]))
			d.lastWasCR = false
			i++
			continue
		}
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size == 1 {
			// Hold an incomplete multi-byte sequence for the next read.  A
			// genuinely invalid byte is dropped rather than rendered as �,
			// which keeps terminal output readable under mixed binary noise.
			if !utf8.FullRune(data[i:]) {
				d.pending = append(d.pending, data[i:]...)
				break
			}
			d.lastWasCR = false
			i++
			continue
		}
		out = append(out, r)
		d.lastWasCR = false
		i += size
	}
	return string(out)
}

func (d *claudeOutputDecoder) flush() string {
	d.pending = nil
	d.lastWasCR = false
	return ""
}

// consumeClaudeEscape returns the byte length of one ANSI/OSC escape.  The
// caller only drops a sequence once its terminator has arrived; incomplete
// sequences are retained in claudeOutputDecoder.pending.
func consumeClaudeEscape(data []byte) (int, bool) {
	if len(data) < 2 || data[0] != 0x1b {
		return 0, false
	}
	switch data[1] {
	case '[': // CSI: final byte is 0x40..0x7e
		for i := 2; i < len(data); i++ {
			if data[i] >= 0x40 && data[i] <= 0x7e {
				return i + 1, true
			}
		}
		return 0, false
	case ']', 'P', '^', '_', 'X': // OSC/DCS/PM/APC; terminated by BEL or ST
		for i := 2; i < len(data); i++ {
			if data[i] == 0x07 {
				return i + 1, true
			}
			if data[i] == 0x1b {
				if i+1 >= len(data) {
					return 0, false
				}
				if data[i+1] == '\\' {
					return i + 2, true
				}
			}
		}
		return 0, false
	case '(', ')', '*', '+', '-', '.', '/', '%', '#':
		// Character-set and DEC private sequences carry one selector byte.
		// Keep the selector out of the transcript as well (for example ESC(B).
		if len(data) < 3 {
			return 0, false
		}
		return 3, true
	default:
		// Two-byte ESC sequences (save/restore cursor, keypad mode, etc.).
		return 2, true
	}
}

func cleanClaudeOutput(value string) string {
	var decoder claudeOutputDecoder
	return decoder.decode([]byte(value))
}

func compactClaudeLog(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 1200 {
		return value[:1200] + "…"
	}
	return value
}
