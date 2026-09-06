// Package store is the issuer's durable state: one SQLite file holding
// enrollments, admin-signed policy, grants, revocations and the issuance log,
// with issuer-managed secrets kept as rows envelope-encrypted under a data key
// resolved through Summon.
//
// This file is a FROZEN CONTRACT owned by the build lead, because
// internal/policy and internal/server both depend on it. Implementations live
// in other files in this package. Propose changes rather than editing.
package store

import (
	"context"
	"errors"
	"time"
)

// Store is the issuer's state. One SQLite file, forward-only migrations run on
// open, so a downgrade is a restore-from-backup rather than a schema rollback.
type Store interface {
	// Migrate runs forward-only migrations. It is called on open and is the
	// only path that changes the schema.
	Migrate(ctx context.Context) error

	// Get and Put move envelope-encrypted rows. The plaintext is encrypted
	// under a data key resolved through Summon, so what SQLite holds is never
	// the value itself.
	//
	// The split this serves is forced rather than chosen: operator-provided
	// secrets are Summon references resolved read-only, while secrets the
	// issuer generates or that rotate on use (GitHub refresh tokens, presence
	// session keys) have to live here, because Summon providers cannot write.
	Get(ctx context.Context, collection, id string) ([]byte, error)
	Put(ctx context.Context, collection, id string, plaintext []byte) error
	Delete(ctx context.Context, collection, id string) error
	List(ctx context.Context, collection string) ([]string, error)

	// RotateDataKey re-encrypts every envelope-encrypted row under a new data
	// key. Losing the old key loses only material a device flow can regenerate,
	// which is why this is survivable at all.
	RotateDataKey(ctx context.Context, next []byte) error

	// Append adds one record to the hash chain and returns its hash. Issuance,
	// exchanges, and policy changes share ONE chain: the spec is explicit that
	// admin-signed policy records are stored in the same chain as issuance, so
	// there is no gap where "which device is enrolled" or "what presence a
	// target needs" lives outside the tamper-evident record.
	Append(ctx context.Context, rec Record) ([]byte, error)

	// Verify walks the chain and reports the first record whose hash does not
	// follow from its predecessor.
	Verify(ctx context.Context) (ok bool, firstBadSeq int64, err error)

	// Walk streams records from seq onward, oldest first, calling fn for each.
	// A tamper-evident log that cannot be read back is write-only: reload has
	// to re-verify what is stored, and an operator has to be able to audit the
	// thing the chain exists to protect.
	//
	// Walk VERIFIES each link as it goes and stops at the first record whose
	// hash does not follow from its predecessor, returning ErrChainBroken
	// after having delivered the valid prefix. Verification is not a separate
	// call a reader may skip, because a reader who walks unverified records is
	// trusting exactly the bytes an attacker would have edited. The valid
	// prefix is still delivered because it is still evidence: where the chain
	// breaks is the most useful fact an operator has.
	//
	// It streams rather than returning a slice because the chain carries every
	// issuance and exchange for the life of the issuer and has no bound.
	//
	// fn returning an error stops the walk and Walk returns that error
	// unchanged, so a caller can stop early without it looking like corruption.
	Walk(ctx context.Context, from int64, fn func(Record) error) error

	// Close releases the database.
	Close() error
}

// Record is one line of the hash-chained log. The chain covers issuance,
// exchange and policy change alike, so a compromised host that mints under the
// CA still cannot quietly widen a grant or enroll a device without leaving a
// break in the chain.
type Record struct {
	// Seq is assigned by the store, not the caller.
	Seq int64
	// Kind distinguishes an issuance from an exchange from a policy change
	// from the issuer's own self-issuance, which the spec requires be its own
	// event type.
	Kind string
	// At is the record time.
	At time.Time
	// Payload is the kind-specific body, already serialised.
	Payload []byte
	// PrevHash is the previous record's hash; Hash covers this record plus it.
	PrevHash []byte
	Hash     []byte
}

// Backup and Restore produce and consume a tarball encrypted under a
// Summon-resolved passphrase.
//
// Restore REQUIRES the provider to be configured first and must say so plainly
// when it is not: a restore that fails halfway because it cannot reach the
// provider is worse than one that refuses at the start, and the operator
// running it has usually just lost a machine.
//
// Restoring an older backup is survivable by design. Devices enrolled after the
// backup fail cleanly and re-enroll, so the correct behavior for an unknown
// device after a restore is a clean refusal that tells it to enroll again,
// never a silent acceptance.
type Backup interface {
	Backup(ctx context.Context, dst string, passphrase []byte) error
	Restore(ctx context.Context, src string, passphrase []byte) error
}

var (
	// ErrNotFound means the collection has no such id.
	ErrNotFound = errors.New("store: no such record")
	// ErrChainBroken means Verify found a record whose hash does not follow
	// from its predecessor. This is tamper evidence, not corruption handling:
	// it must be reported loudly and must never be repaired automatically.
	ErrChainBroken = errors.New("store: hash chain is broken")
	// ErrProviderNotConfigured is what Restore returns when no Summon provider
	// is configured yet, before it has touched anything.
	ErrProviderNotConfigured = errors.New("store: restore needs the Summon provider configured first")
	// ErrSchemaAhead means the file was written by a newer issuer. Migrations
	// are forward-only, so the fix is to restore a backup rather than to
	// downgrade the schema in place.
	ErrSchemaAhead = errors.New("store: database schema is newer than this binary")
)
