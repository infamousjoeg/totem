// Package attest answers one question: which catalog tool is on the other end
// of this socket? It is the tool-identity anchor, and it is deliberately
// unforgiving. Peer credentials give the pid; a start-time check closes pid
// reuse; the binary is hash-pinned and its Mach-O code signature is parsed in
// pure Go for Team ID plus signing identifier; one OS-signed shell hop is
// tolerated in the parent walk and no more. Default deny: a process that does
// not resolve to a catalog entry gets no identity.
//
// This file is the FROZEN CONTRACT between the attestation implementation and
// its callers (internal/workloadapi, cmd/totem). It is owned by the build lead.
// Implementations live in other files in this package. Do not change the
// signatures here without asking the lead: other teammates are compiling
// against them right now.
package attest

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

// Peer is what the kernel tells us about the process on the other end of an
// accepted unix connection, before any policy is applied. StartTime is the
// load-bearing field: a pid alone is reusable, a pid plus its start time is
// not, so every check re-reads it and refuses if it moved.
type Peer struct {
	// PID of the connecting process.
	PID int32
	// UID the connecting process runs as. A dedicated OS uid is how an agent
	// identity falls out of the unix attestor for free.
	UID uint32
	// GID the connecting process runs as.
	GID uint32
	// StartTime of the process, read at the same moment as the pid. If this
	// changes between checks, the pid was reused and attestation must fail.
	StartTime time.Time
	// BinaryPath is the resolved on-disk path of the connecting executable.
	BinaryPath string
}

// Identity is a successful attestation: this connection is that catalog tool,
// and here is every fact the issuer will be asked to stand behind. It is the
// input to the derived SPIFFE ID and to the audit record; nothing here is
// self-reported by the caller.
type Identity struct {
	// Tool is the catalog name, e.g. "claude". It becomes the tool-name
	// segment of spiffe://<trust-domain>/device/<device-id>/tool/<tool-name>.
	Tool string
	// Entry is the catalog row that matched.
	Entry spiffe.CatalogEntry
	// Peer is the attested process.
	Peer Peer
	// BinaryHash is the SHA-256 of the binary that was pinned, hex-encoded.
	BinaryHash string
	// TeamID is the Apple Developer Team Identifier read from the code
	// signature. Empty on Linux.
	TeamID string
	// SigningID is the code-signing identifier read from the code signature.
	// Empty on Linux.
	SigningID string
	// ParentChain is the walk from the connecting process up to the catalog
	// binary, resolved paths in child-to-parent order. It is recorded so an
	// audit line can show exactly how the identity was reached.
	ParentChain []string
	// ShellHops is how many OS-signed shell processes the walk crossed. The
	// spec allows exactly one; more is a refusal, not a warning.
	ShellHops int
	// PathProtected records whether the binary and every parent directory were
	// non-user-writable.
	//
	// It is false for a normal Claude Code install and that is not a bug: both
	// shipped catalog paths (~/.local/share/claude/versions/* and the Homebrew
	// prefix) are owned by the console user on a real Mac, because the Homebrew
	// prefix is user-owned by design. A strict path check would therefore
	// refuse every genuine install, so path protection is NOT the control for
	// catalog binaries. The control is the chain-verified vendor signature plus
	// the kernel cdhash cross-check; see ErrUnsignedAtWritablePath.
	//
	// It is still recorded because it is a real difference in assurance, it
	// belongs in the audit line, and issuer policy may later require presence
	// for tools that ran from a writable path. Never silently upgrade a false
	// to a true.
	PathProtected bool
}

// Attestor resolves a connection to a tool identity.
type Attestor interface {
	// AttestPeer inspects the process on the other end of an already-accepted
	// unix connection and returns its catalog identity, or an error.
	//
	// Callers: the Workload API server accepts on a unix listener and must
	// capture the *net.UnixConn before gRPC wraps it, attest it once, and carry
	// the resulting *Identity on the connection's context for the lifetime of
	// that connection. Attestation is per-connection, not per-RPC, and is
	// re-checked (start time, hash) on renewal.
	AttestPeer(ctx context.Context, conn *net.UnixConn) (*Identity, error)
}

// New returns the Attestor for this machine, loaded against catalog and pins.
// Passing a nil catalog uses spiffe.Catalog.
//
// pins maps a catalog tool name to the hex SHA-256 the binary was pinned to at
// `totem init`. Pin-on-init is the default anchor: a pinned tool whose hash no
// longer matches is a refusal, not a warning. A nil or absent pin means the
// chain-verified Team ID plus signing identifier is the anchor instead, and the
// observed hash is recorded rather than enforced.
//
// pins is a required parameter rather than a second constructor or a setter,
// because a caller that never supplies pins would otherwise get the weaker
// anchor silently. Passing nil must be a visible decision at the call site.
//
// On Linux there is no code signature to fall back on, so a catalog match
// REQUIRES a pin; without one the tool gets no identity.
//
// Implemented by the attest teammate. Declared here so callers can compile.
var New func(catalog []spiffe.CatalogEntry, pins map[string]string) (Attestor, error)

// Errors are typed so the Workload API can answer a rejected caller legibly
// (the spec's rejection-UX rule) instead of returning a bare permission error.
var (
	// ErrNotInCatalog means the binary resolved fine but is not a tool totem
	// issues identities for. This is the default-deny path and it is the
	// common, boring rejection.
	ErrNotInCatalog = errors.New("attest: binary is not in the tool catalog")
	// ErrSignatureMismatch means the binary is at a catalog path but its Team
	// ID, signing identifier, or hash does not match the catalog row.
	ErrSignatureMismatch = errors.New("attest: code signature does not match catalog entry")
	// ErrPIDReused means the process start time moved between reads, so the pid
	// no longer refers to the process that connected.
	ErrPIDReused = errors.New("attest: pid was reused during attestation")
	// ErrTooManyShellHops means the parent walk crossed more than the one
	// OS-signed shell hop the spec allows.
	ErrTooManyShellHops = errors.New("attest: parent walk crossed more than one shell hop")
	// ErrInterpreterWrapped means the caller is a script under an interpreter,
	// which cannot be attested and gets no identity by design.
	ErrInterpreterWrapped = errors.New("attest: interpreter-wrapped callers get no identity")
	// ErrUnsignedAtWritablePath means the binary sits at a user-writable path
	// and does not carry a fully chain-verified vendor signature, so nothing
	// stops the user (or malware running as them) from replacing it. Catalog
	// binaries are allowed to live at writable paths only because the signature
	// chain and the kernel cdhash cross-check take over as the control there;
	// an ad-hoc or unsigned binary has neither and is refused.
	ErrUnsignedAtWritablePath = errors.New("attest: unsigned binary at a user-writable path")
	// ErrChainChanged is returned by Recheck (see Rechecker) when the
	// connecting process is still the one that was attested but the walk from
	// it no longer reaches the same catalog tool: typically the shell hop or
	// the tool exited and the helper was reparented. It is a lifecycle event,
	// not a refusal of an untrusted caller, and it is typed separately so an
	// audit line can tell the two apart. The underlying reason is wrapped.
	ErrChainChanged = errors.New("attest: parent chain changed since attestation")
)

// Every typed error this package returns is declared in the block above. A
// caller mapping rejections to statuses can treat that block as the complete
// surface; a new error belongs there, not in an implementation file.
