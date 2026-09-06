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

	"github.com/infamousjoeg/totem/internal/attest"
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
	// PathProtected records whether the caller's binary and every parent
	// directory were non-user-writable at the moment it was attested.
	//
	// It is recorded, never acted on. It is false for a normal Claude Code
	// install because the Homebrew prefix is user-owned by design, so path
	// protection is not the control for catalog binaries; the chain-verified
	// signature and the kernel cdhash cross-check are. It is kept because it is
	// a real difference in assurance that belongs in the audit line, and
	// because issuer policy may one day want presence for a tool that ran from
	// a writable path. `totem log` does not show it in normal operation: a
	// false here is the ordinary case and surfacing it would train people to
	// ignore a real warning later.
	PathProtected bool `json:"path_protected,omitempty"`
	// ShellHops is how many OS-signed shell processes the parent walk crossed
	// to reach the attested tool. Recorded for the same reason.
	ShellHops int `json:"shell_hops,omitempty"`
	// ParentChain is the walk from the connecting process up to the catalog
	// binary, so an audit line shows exactly how the identity was reached.
	// Only written under a verbose logger.
	ParentChain []string `json:"parent_chain,omitempty"`
}

// EventFor builds a log event carrying every fact attestation established
// about a caller. It is the single place the audit line is assembled, so a
// field cannot be recorded on a refusal and forgotten on an issuance.
func EventFor(kind string, ident *attest.Identity, err error) Event {
	ev := Event{Kind: kind}
	if ident != nil {
		ev.Tool = ident.Tool
		ev.PID = ident.Peer.PID
		ev.PathProtected = ident.PathProtected
		ev.ShellHops = ident.ShellHops
		ev.ParentChain = ident.ParentChain
	}
	if err != nil {
		ev.Reason = reasonFor(err)
		ev.Message = humanRefusal(err, ident)
		ev.Fix = fixFor(err, ident)
	}
	return ev
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
