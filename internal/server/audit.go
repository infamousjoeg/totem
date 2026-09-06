package server

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/infamousjoeg/totem/internal/presence"
)

// docs/totem-design.md "Issuer (broker box)": "Every issuance, exchange, and
// policy change is one structured, hash-chained log line: SPIFFE ID, device,
// tool anchor, presence type and age, grant ID, outcome. Stdout, with optional
// syslog or OTLP export."
//
// One line per event, and the chain is what makes the stream tamper-evident on
// its way off the box. Two decisions here are worth stating because getting
// either wrong makes the chain decorative:
//
//   - The hash is computed over a CANONICAL encoding built field by field with
//     explicit length prefixes, not over the JSON. JSON is not canonical: key
//     order, escaping, and float formatting are all free, so a verifier that
//     re-marshals a parsed line can produce different bytes than the writer did
//     and conclude the chain is broken when nothing tampered with it. The same
//     length-prefix discipline internal/presence uses for signing inputs
//     applies for the same reason: no field boundary can be shifted, so
//     ("ab","c") and ("a","bc") never hash alike.
//   - The event Kind is passed through from whoever produced the event, never
//     chosen here. internal/ca hands back ca.EventIssuerSelfIssuance on the
//     SVID it mints for the issuer's own identity precisely so a self-issuance
//     can never be logged as a device issuance, and re-deciding the label at
//     the log call would throw that guarantee away. Audit event kinds are
//     constants in internal/ca and internal/policy; this package defines only
//     the ones that describe its own front-door events.

// Front-door event kinds. Everything else that reaches the log arrives with a
// kind from internal/ca (issuance, self-issuance, rotation, revocation) or
// internal/policy (policy/<action>).
const (
	// EventEnrollment is one enrollment attempt, approved or pending.
	EventEnrollment = "enrollment"
	// EventBootstrapIssued is a bootstrap code minted at init or recover. It
	// records THAT a code was minted and when it expires, never the code.
	EventBootstrapIssued = "issuer.bootstrap_issued"
	// EventBootstrapRedeemed is a bootstrap code spent by an enrolling device.
	// "Redemption logged with the device fingerprint": the fingerprint is what
	// makes a stolen-code incident reconstructable, and it is safe to log
	// because it identifies the device rather than authorising anything.
	EventBootstrapRedeemed = "issuer.bootstrap_redeemed"
	// EventRefused is a request the front door turned away before it reached
	// the policy engine: an unrecognised credential, an incompatible agent, a
	// malformed body.
	EventRefused = "refused"
)

// Event is one audit line. Every field the spec names is here, and there is
// deliberately no free-form field and no field that could carry a secret: a
// log line the issuer ships off the box is the last place a bootstrap code, a
// resolved secret, or a private key should be able to appear, and the way to
// guarantee that is for there to be nowhere to put one.
type Event struct {
	// Kind is the event kind, passed through from its producer.
	Kind string
	// SpiffeID of the identity a credential was issued to, when there is one.
	SpiffeID string
	// Device the event concerns: a device id, or a pre-enrollment fingerprint
	// for an enrollment that has not been assigned one yet.
	Device string
	// ToolAnchor is the catalog anchor the caller attested against.
	ToolAnchor string
	// Target of the request, as the human would have been shown it.
	Target string
	// Presence is the presence state that authorised the event. StateNone is a
	// recorded value, not a missing one.
	Presence presence.State
	// PresenceAge is how old the covering presence assertion was.
	PresenceAge time.Duration
	// GrantID ties a delegated event to the human's signed grant.
	GrantID string
	// Signer is the device that signed a policy record.
	Signer string
	// AgentVersion is the version the calling agent reported, or "unknown".
	AgentVersion string
	// Outcome is what happened: "approved", "pending", "refused", "issued".
	Outcome string
	// Reason is the machine token for a refusal, from internal/errors.
	Reason string
}

// Record is one written line: the event, its position, and the chain.
type Record struct {
	Seq          int64     `json:"seq"`
	At           time.Time `json:"at"`
	Kind         string    `json:"kind"`
	SpiffeID     string    `json:"spiffe_id,omitempty"`
	Device       string    `json:"device,omitempty"`
	ToolAnchor   string    `json:"tool_anchor,omitempty"`
	Target       string    `json:"target,omitempty"`
	Presence     string    `json:"presence,omitempty"`
	PresenceAgeS *int64    `json:"presence_age_s,omitempty"`
	GrantID      string    `json:"grant_id,omitempty"`
	Signer       string    `json:"signer,omitempty"`
	AgentVersion string    `json:"agent_version,omitempty"`
	Outcome      string    `json:"outcome,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	PrevHash     string    `json:"prev"`
	Hash         string    `json:"hash"`
}

// AuditLog writes the hash-chained stream. It is safe for concurrent use: the
// chain is a sequence, and two goroutines appending to it without a lock
// produce two records claiming the same predecessor, which reads downstream as
// tampering.
type AuditLog struct {
	mu   sync.Mutex
	w    io.Writer
	enc  *json.Encoder
	now  func() time.Time
	seq  int64
	prev []byte
}

// GenesisHash is the predecessor of the first record: thirty-two zero bytes. A
// verifier starting from the beginning of a stream knows what to expect.
var GenesisHash = make([]byte, sha256.Size)

// NewAuditLog returns a log writing one JSON object per line to w.
func NewAuditLog(w io.Writer, now func() time.Time) *AuditLog {
	if now == nil {
		now = time.Now
	}
	return &AuditLog{w: w, enc: json.NewEncoder(w), now: now, prev: GenesisHash}
}

// Log appends one event and returns the record as written.
func (l *AuditLog) Log(e Event) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	rec := Record{
		Seq:          l.seq,
		At:           l.now().UTC(),
		Kind:         e.Kind,
		SpiffeID:     e.SpiffeID,
		Device:       e.Device,
		ToolAnchor:   e.ToolAnchor,
		Target:       e.Target,
		Presence:     string(e.Presence),
		GrantID:      e.GrantID,
		Signer:       e.Signer,
		AgentVersion: e.AgentVersion,
		Outcome:      e.Outcome,
		Reason:       e.Reason,
		PrevHash:     hex.EncodeToString(l.prev),
	}
	// Presence age is a pointer so "zero seconds" and "no presence involved"
	// are distinguishable in the stream. An auditor reading presence_age_s: 0
	// on a line with no presence would otherwise conclude a human touched the
	// sensor at exactly the instant of issuance.
	if e.Presence != "" {
		secs := int64(e.PresenceAge / time.Second)
		rec.PresenceAgeS = &secs
	}
	sum := chainHash(l.prev, rec)
	rec.Hash = hex.EncodeToString(sum)

	if err := l.enc.Encode(rec); err != nil {
		return Record{}, err
	}
	l.prev = sum
	l.seq++
	return rec, nil
}

// Head returns the hash of the last record written, so a caller can hand the
// chain's tip to a verifier or to durable storage.
func (l *AuditLog) Head() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.prev...)
}

// chainHash is the canonical hash of one record: SHA-256 over the previous
// hash and every field, each length-prefixed, in a fixed order.
func chainHash(prev []byte, r Record) []byte {
	h := sha256.New()
	write := func(b []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	write([]byte("totem/audit-chain"))
	write(prev)
	write([]byte(strconv.FormatInt(r.Seq, 10)))
	write([]byte(r.At.Format(time.RFC3339Nano)))
	write([]byte(r.Kind))
	write([]byte(r.SpiffeID))
	write([]byte(r.Device))
	write([]byte(r.ToolAnchor))
	write([]byte(r.Target))
	write([]byte(r.Presence))
	if r.PresenceAgeS == nil {
		write(nil)
	} else {
		write([]byte(strconv.FormatInt(*r.PresenceAgeS, 10)))
	}
	write([]byte(r.GrantID))
	write([]byte(r.Signer))
	write([]byte(r.AgentVersion))
	write([]byte(r.Outcome))
	write([]byte(r.Reason))
	return h.Sum(nil)
}

// VerifyChain walks records in order and reports the first whose hash does not
// follow from its predecessor. It is the reader's half of the chain, and it
// exists in this package so the writer and the verifier are built from the same
// canonical encoder rather than from two readings of a format description.
func VerifyChain(records []Record) (ok bool, firstBad int64) {
	prev := GenesisHash
	for _, r := range records {
		if hex.EncodeToString(prev) != r.PrevHash {
			return false, r.Seq
		}
		want := chainHash(prev, r)
		if hex.EncodeToString(want) != r.Hash {
			return false, r.Seq
		}
		prev = want
	}
	return true, 0
}
