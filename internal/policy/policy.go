// Package policy holds the admin-signed record types: enrollments, the
// hash-chained audit line, and the shipped-default posture. Scaffold only:
// types and doc comments, no signing, chaining, or evaluation logic.
package policy

import (
	"time"

	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/spiffe"
)

// EnrollmentRecord is what the issuer records for a device: the public key,
// device ID, protection level, and pinned cert. Only admin devices can approve
// enrollments, and revoking the last admin is refused.
type EnrollmentRecord struct {
	// DeviceID is the derived identifier for the enrolled device.
	DeviceID string
	// PublicKey is the device's enrolled public key (attestation re-checks
	// against it silently on every renewal).
	PublicKey []byte
	// ProtectionLevel is the assurance of the device key, carried on the
	// identity so downstream policy can act on it.
	ProtectionLevel spiffe.ProtectionLevel
	// PinnedCert is the issuer certificate the device pinned at enroll.
	PinnedCert []byte
	// Admin marks a device that may approve enrollments; approve, grant-admin,
	// revoke-admin, and revoke are presence:always regardless of the device's
	// windows.
	Admin bool
	// ApprovedByPresence records whether the approving admin was present; an
	// approval by a presence:none admin is recorded as such on the new
	// enrollment.
	ApprovedByPresence presence.State
	// LastSeen is the last time the device was observed.
	LastSeen time.Time
}

// AuditRecord is one structured, hash-chained log line: every issuance and
// exchange records the SPIFFE ID, device, tool anchor, presence type and age,
// and outcome. The chain makes the log tamper-evident; config and policy
// changes are logged the same way so the honest threat model has no gap where
// "which device is enrolled / what presence a target needs" lives.
type AuditRecord struct {
	// SpiffeID of the identity the credential was issued to.
	SpiffeID string
	// Device the credential was bound to.
	Device string
	// ToolAnchor is the catalog anchor the caller attested against.
	ToolAnchor string
	// Presence is the presence state that authorized the issuance.
	Presence presence.State
	// PresenceAgeSeconds is how old the presence assertion was at issuance.
	PresenceAgeSeconds int
	// GrantID is set when Presence is delegated, tying the action to the
	// human's signed grant so every delegated credential answers "who
	// authorized this."
	GrantID string
	// Outcome is the result of the issuance or exchange.
	Outcome string
	// PrevHash is the hash of the previous record; Hash chains this one to it.
	PrevHash []byte
	// Hash is this record's hash over its fields plus PrevHash.
	Hash []byte
}

// Default is the shipped posture. Default deny in every policy file shipped: an
// identity, target, or tool not explicitly granted gets nothing.
const Default = "deny"
