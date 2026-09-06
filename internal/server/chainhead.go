package server

import (
	"context"
	"encoding/hex"

	"github.com/infamousjoeg/totem/internal/store"
)

// ChainHeadReason says why a head line was emitted. The set is closed because
// the value of these lines is comparing one against the next, and a reader
// doing that needs to know whether a gap between two heads is a process that
// restarted or a restore that moved the chain.
type ChainHeadReason string

const (
	// ChainHeadAtOpen is the issuer opening its state.
	ChainHeadAtOpen ChainHeadReason = "open"
	// ChainHeadAfterRestore is a restore having completed. A head that moved
	// BACKWARDS across one of these is expected; across two "open" lines it is
	// not, and that difference is the whole reason the reason is recorded.
	ChainHeadAfterRestore ChainHeadReason = "restore"
)

// LogChainHead emits the durable chain's tip as one audit line.
//
// See EventChainHead for what this buys and, more importantly, what it does
// not: it detects an operator error or a clumsy rollback and does not detect a
// competent attacker, who holds the log emitter along with the host. The real
// fix is the fleet witness that lands with the versioned agent protocol.
//
// There is deliberately NO comparison here against a previously recorded head,
// and no refusal to start. A witness the host writes for itself is not a
// witness: the same host that truncated the chain can rewrite a local file
// recording where it used to end. Building that check would produce exactly the
// false confidence this line is written to avoid, so the only thing this does
// is state the value and let it leave the box.
//
// A failure to read the head is returned rather than swallowed. Being unable to
// answer "where does my chain end" at open is a real fault in the state file,
// and it is the caller's decision whether to proceed, not this function's.
func LogChainHead(ctx context.Context, log *AuditLog, s store.Store, reason ChainHeadReason) error {
	seq, hash, err := s.Head(ctx)
	if err != nil {
		return err
	}
	// Sequence zero with a nil hash means nothing has been appended, which is
	// a legitimate state for a freshly initialised issuer and is worth saying
	// out loud rather than omitting: "the chain is empty" and "the head was not
	// reported" must not look alike to whatever is reading the shipped stream.
	_, err = log.Log(Event{
		Kind:      EventChainHead,
		Outcome:   string(reason),
		ChainSeq:  &seq,
		ChainHash: hex.EncodeToString(hash),
	})
	return err
}
