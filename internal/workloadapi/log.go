package workloadapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event kinds. docs/totem-design.md "Experience": `totem log` records refusals,
// prompts, and failures by default; successes are counted, not listed, and
// --verbose opts into the full local record.
const (
	// KindRefusal is a caller that was denied an identity or a credential.
	KindRefusal = "refusal"
	// KindPrompt is a presence prompt shown to the human.
	KindPrompt = "prompt"
	// KindFailure is an internal failure that is nobody's rejection.
	KindFailure = "failure"
	// KindIssuance is a successful issuance. It is written but not listed
	// unless `totem log --verbose` asks for it.
	KindIssuance = "issuance"
)

// Event is one line of the agent's local structured log. Calling tools swallow
// helper stderr, so this file is where a refusal is actually legible after the
// fact; `totem status` surfaces it first and `totem log` reads it back.
type Event struct {
	// Time is when the event happened, in UTC.
	Time time.Time `json:"time"`
	// Kind is one of the Kind constants above.
	Kind string `json:"kind"`
	// Tool is the catalog tool involved, when one was resolved.
	Tool string `json:"tool,omitempty"`
	// SpiffeID is the derived identity involved, when one was derived.
	SpiffeID string `json:"spiffe_id,omitempty"`
	// Reason is the short machine token, matching ~/.totem/last-error.
	Reason string `json:"reason,omitempty"`
	// Message is the one-line plain-language description.
	Message string `json:"message,omitempty"`
	// Fix is the exact command or action that resolves it.
	Fix string `json:"fix,omitempty"`
	// PID is the calling process, when one was attested.
	PID int32 `json:"pid,omitempty"`
}

// Logger appends events to the agent's local log as JSON lines. It is
// deliberately dumb: one file, append-only, 0600, no rotation policy beyond a
// size cap, because a log a person cannot read at 2am is not a log.
type Logger struct {
	path string
	mu   sync.Mutex
}

// DefaultLogPath is ~/.totem/log.jsonl.
func DefaultLogPath() string { return filepath.Join(homeDir(), ".totem", "log.jsonl") }

// NewLogger returns a Logger appending to path. An empty path means the default
// location. The file and its directory are created at 0600 and 0700.
func NewLogger(path string) *Logger {
	if path == "" {
		path = DefaultLogPath()
	}
	return &Logger{path: path}
}

// Path is the file this logger writes to.
func (l *Logger) Path() string { return l.path }

// Record appends one event. A logging failure is never allowed to break an
// exchange, so errors here are dropped: the gRPC status the caller receives is
// the primary channel and this file is the durable copy.
func (l *Logger) Record(ev Event) {
	if l == nil {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(l.path), DirMode); err != nil {
		return
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

// ReadEvents reads the log back, newest last, capped at limit lines (0 means
// all). A missing log is not an error: an agent that has refused nothing has
// nothing to show.
func ReadEvents(path string, limit int) ([]Event, error) {
	if path == "" {
		path = DefaultLogPath()
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var events []Event
	dec := json.NewDecoder(bytes.NewReader(data))
	for dec.More() {
		var ev Event
		if err := dec.Decode(&ev); err != nil {
			// A truncated final line from a crash is skipped, not fatal.
			break
		}
		events = append(events, ev)
	}
	if limit > 0 && len(events) > limit {
		events = events[len(events)-limit:]
	}
	return events, nil
}
