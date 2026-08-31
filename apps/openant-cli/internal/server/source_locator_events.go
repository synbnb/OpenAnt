package server

// Filesystem-backed event replay for source-locator sessions.  Python owns the
// event schema and append-only writes; Go only reads bounded, validated JSONL
// records for the browser's SSE connection.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	maxSourceLocatorEventLineBytes = 64 << 10
	maxSourceLocatorEventFileBytes = 16 << 20
)

type sourceLocatorEvent struct {
	SchemaVersion string         `json:"schema_version"`
	Seq           int            `json:"seq"`
	SessionID     string         `json:"session_id"`
	Type          string         `json:"type"`
	State         string         `json:"state"`
	SummaryZH     string         `json:"summary_zh"`
	Artifact      string         `json:"artifact"`
	EvidenceIDs   []string       `json:"evidence_ids"`
	Details       map[string]any `json:"details"`
	CreatedAt     string         `json:"created_at"`
}

func (e sourceLocatorEvent) validFor(sessionID string, expectedSeq int) bool {
	if e.SchemaVersion != "openant.source-locator.event.v1" || e.Seq != expectedSeq || e.SessionID != sessionID {
		return false
	}
	if e.Type == "" || e.State == "" || e.SummaryZH == "" || e.CreatedAt == "" {
		return false
	}
	return true
}

// readSourceLocatorEvents reads only complete JSONL records.  A writer may be
// in the middle of appending the final line; that line is deferred to the next
// poll rather than treated as a corrupted session.
func readSourceLocatorEvents(root, sessionID string, after int) ([]sourceLocatorEvent, int, error) {
	if after < 0 {
		return nil, after, fmt.Errorf("事件序号不能为负数")
	}
	if !sourceLocatorSessionIDRe.MatchString(sessionID) {
		return nil, after, fmt.Errorf("无效的 source-locator session ID")
	}
	sessionDir := filepath.Join(root, sessionID)
	if !withinRoot(root, sessionDir) {
		return nil, after, fmt.Errorf("session 路径越界")
	}
	path := filepath.Join(sessionDir, "events.jsonl")
	f, fi, err := openRegularInRoot(root, path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, after, nil
		}
		return nil, after, err
	}
	defer f.Close()
	if fi.Size() > maxSourceLocatorEventFileBytes {
		return nil, after, fmt.Errorf("事件文件超过大小上限")
	}

	var events []sourceLocatorEvent
	lastSeq := 0
	reader := bufio.NewReader(io.LimitReader(f, maxSourceLocatorEventFileBytes))
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > maxSourceLocatorEventLineBytes {
			return nil, lastSeq, fmt.Errorf("单条事件超过大小上限")
		}
		raw := strings.TrimSpace(string(line))
		if raw == "" {
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return nil, lastSeq, readErr
			}
			continue
		}
		var event sourceLocatorEvent
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			// A non-newline-terminated, partially written final record is retried
			// on the next poll.  Any malformed complete middle record fails closed.
			if readErr == io.EOF {
				break
			}
			return nil, lastSeq, fmt.Errorf("事件记录不是有效 JSON")
		}
		if !event.validFor(sessionID, lastSeq+1) {
			return nil, lastSeq, fmt.Errorf("事件记录序号、session 或 schema 无效")
		}
		lastSeq = event.Seq
		if event.Seq > after {
			events = append(events, event)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, lastSeq, readErr
		}
	}
	return events, lastSeq, nil
}

func formatSourceLocatorSSEEvent(event sourceLocatorEvent) string {
	payload, err := json.Marshal(event)
	if err != nil {
		return ""
	}
	return "id: " + strconv.Itoa(event.Seq) + "\nevent: locator\ndata: " + string(payload) + "\n\n"
}
