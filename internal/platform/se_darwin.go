//go:build darwin && cgo

package platform

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security -framework LocalAuthentication
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <stdlib.h>
#include <string.h>

// totem_err carries a CFError back to Go: domain and code are what the error
// mapping keys on, desc is for the wrapped message.
typedef struct {
	long code;
	char domain[64];
	char desc[240];
} totem_err;

static void totem_fill_err(totem_err *e, CFErrorRef err) {
	memset(e, 0, sizeof(*e));
	if (!err) return;
	NSError *ns = (__bridge NSError *)err;
	e->code = (long)ns.code;
	strncpy(e->domain, ns.domain.UTF8String ?: "", sizeof(e->domain) - 1);
	NSString *d = ns.localizedDescription ?: @"";
	strncpy(e->desc, d.UTF8String ?: "", sizeof(e->desc) - 1);
}

static void *totem_copy_bytes(NSData *d, size_t *len) {
	*len = (size_t)d.length;
	void *out = malloc(*len ? *len : 1);
	memcpy(out, d.bytes, *len);
	return out;
}

// The Secure Enclave token identifier for its keys. This is the value
// SecKeyCopyAttributes returns under kSecAttrTokenOID for a Secure Enclave
// key: the SEP-wrapped key blob, which is what CryptoKit exposes as
// dataRepresentation. It only loads on the Secure Enclave that produced it.
// kSecAttrTokenOID is not declared in the public SDK headers, so its string
// value is used directly; see the package report for the trade-off.
static NSString *const totemTokenOID = @"toid";

// totem_se_create makes a Secure Enclave P-256 key. With presence != 0 the
// access control carries kSecAccessControlUserPresence, which the Secure
// Enclave enforces on every signature (biometry or device password); without
// it only kSecAccessControlPrivateKeyUsage is set. The key is not stored in a
// keychain (kSecAttrIsPermanent false): its wrapped blob is returned to the
// caller for storage and re-imported with totem_se_load.
static int totem_se_create(int presence, void **blob, size_t *bloblen, void **pub, size_t *publen, totem_err *e) {
	CFErrorRef err = NULL;
	SecAccessControlCreateFlags flags = kSecAccessControlPrivateKeyUsage;
	if (presence) flags |= kSecAccessControlUserPresence;
	SecAccessControlRef acl = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
		kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags, &err);
	if (!acl) { totem_fill_err(e, err); if (err) CFRelease(err); return 0; }
	NSDictionary *attrs = @{
		(id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
		(id)kSecAttrKeySizeInBits: @256,
		(id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
		(id)kSecPrivateKeyAttrs: @{
			(id)kSecAttrIsPermanent: @NO,
			(id)kSecAttrAccessControl: (__bridge id)acl,
		},
	};
	SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &err);
	CFRelease(acl);
	if (!key) { totem_fill_err(e, err); if (err) CFRelease(err); return 0; }
	NSDictionary *ka = CFBridgingRelease(SecKeyCopyAttributes(key));
	NSData *oid = ka[totemTokenOID];
	SecKeyRef pk = SecKeyCopyPublicKey(key);
	NSData *pubData = pk ? CFBridgingRelease(SecKeyCopyExternalRepresentation(pk, &err)) : nil;
	if (pk) CFRelease(pk);
	CFRelease(key);
	if (!oid || !pubData) {
		totem_fill_err(e, err); if (err) CFRelease(err);
		if (!e->code) { e->code = -1; strncpy(e->desc, "Secure Enclave key has no token blob or public key", sizeof(e->desc) - 1); }
		return 0;
	}
	*blob = totem_copy_bytes(oid, bloblen);
	*pub = totem_copy_bytes(pubData, publen);
	return 1;
}

// totem_se_load re-imports a wrapped blob as a Secure Enclave key reference.
// ctx, when non-NULL, is the LAContext the Secure Enclave's access control
// will evaluate at signing time; its interactionNotAllowed flag is what makes
// a Required=false signature structurally unable to prompt.
static SecKeyRef totem_se_load(const void *blob, size_t bloblen, LAContext *ctx, totem_err *e) {
	CFErrorRef err = NULL;
	NSData *b = [NSData dataWithBytes:blob length:bloblen];
	NSMutableDictionary *attrs = [@{
		(id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
		(id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate,
		(id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
		totemTokenOID: b,
	} mutableCopy];
	if (ctx) attrs[(id)kSecUseAuthenticationContext] = ctx;
	SecKeyRef key = SecKeyCreateWithData((__bridge CFDataRef)b, (__bridge CFDictionaryRef)attrs, &err);
	if (!key) { totem_fill_err(e, err); if (err) CFRelease(err); return NULL; }
	return key;
}

static int totem_se_public(const void *blob, size_t bloblen, void **pub, size_t *publen, totem_err *e) {
	SecKeyRef key = totem_se_load(blob, bloblen, nil, e);
	if (!key) return 0;
	CFErrorRef err = NULL;
	SecKeyRef pk = SecKeyCopyPublicKey(key);
	NSData *pubData = pk ? CFBridgingRelease(SecKeyCopyExternalRepresentation(pk, &err)) : nil;
	if (pk) CFRelease(pk);
	CFRelease(key);
	if (!pubData) { totem_fill_err(e, err); if (err) CFRelease(err); return 0; }
	*pub = totem_copy_bytes(pubData, publen);
	return 1;
}

// totem_la_new builds the LocalAuthentication context for one signature. The
// reason is shown verbatim in the system prompt ("totem is trying to ...").
// interactive == 0 sets interactionNotAllowed, so any access control that
// needs a human fails instead of prompting.
static void *totem_la_new(const char *reason, int interactive) {
	LAContext *ctx = [[LAContext alloc] init];
	ctx.localizedReason = [NSString stringWithUTF8String:reason];
	ctx.interactionNotAllowed = interactive ? NO : YES;
	return (void *)CFBridgingRetain(ctx);
}

static void totem_la_invalidate(void *p) {
	LAContext *ctx = (__bridge LAContext *)p;
	[ctx invalidate];
}

static void totem_la_free(void *p) {
	CFBridgingRelease(p);
}

// totem_la_can reports whether LAPolicyDeviceOwnerAuthentication (biometry or
// device password) can be evaluated, and the LAError code when it cannot.
static int totem_la_can(long *code) {
	LAContext *ctx = [[LAContext alloc] init];
	NSError *err = nil;
	BOOL ok = [ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&err];
	*code = ok ? 0 : (long)err.code;
	return ok ? 1 : 0;
}

static int totem_la_biometry(void) {
	LAContext *ctx = [[LAContext alloc] init];
	NSError *err = nil;
	BOOL ok = [ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&err];
	return ok ? 1 : 0;
}

// totem_se_sign signs a 32-byte SHA-256 digest with the key in blob under
// the given LAContext. The signature is ECDSA X9.62 DER (SEQUENCE of r, s).
static int totem_se_sign(const void *blob, size_t bloblen, void *lactx, const void *digest, size_t dlen,
	void **sig, size_t *siglen, totem_err *e) {
	LAContext *ctx = (__bridge LAContext *)lactx;
	SecKeyRef key = totem_se_load(blob, bloblen, ctx, e);
	if (!key) return 0;
	CFErrorRef err = NULL;
	NSData *d = [NSData dataWithBytes:digest length:dlen];
	CFDataRef s = SecKeyCreateSignature(key, kSecKeyAlgorithmECDSASignatureDigestX962SHA256, (__bridge CFDataRef)d, &err);
	CFRelease(key);
	if (!s) { totem_fill_err(e, err); if (err) CFRelease(err); return 0; }
	*sig = totem_copy_bytes((__bridge NSData *)s, siglen);
	CFRelease(s);
	return 1;
}
*/
import "C"

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

// ErrIncompletePrompt means Sign was asked for a presence check without a
// tool, target, or device to show the human. The spec requires the prompt to
// name all three; an anonymous approval is refused rather than shown.
var ErrIncompletePrompt = errors.New("platform: presence prompt must name tool, target, and device")

// defaultPresenceTimeout bounds a presence prompt when the caller's context
// has no deadline. A prompt nobody answers is a denial, not a hang.
const defaultPresenceTimeout = 2 * time.Minute

// SecureEnclaveStore is the macOS hardware level. Each label holds two Secure
// Enclave P-256 keys, both non-exportable:
//
//   - the device key, with kSecAccessControlPrivateKeyUsage only, which signs
//     silently (device SVID renewal at half-life, Prompt.Required == false);
//   - the companion presence key, whose access control also carries
//     kSecAccessControlUserPresence, so the Secure Enclave itself refuses to
//     sign until the human passes Touch ID or the device password. This is the
//     "companion key created with a user-presence access control" from the
//     design; the gate lives in the key's ACL, not in this package's control
//     flow, so a same-user process that calls the signing path directly still
//     hits the prompt.
//
// The keys are not kept in a keychain (that needs a keychain-access-groups
// entitlement, i.e. Developer ID signing); their SEP-wrapped blobs live in a
// 0600 file and only load on this Secure Enclave. Residency is trust-on-first-
// use, recorded as unattested, per the design.
type SecureEnclaveStore struct {
	dir string
}

// seRecord is the on-disk record: the wrapped device key blob and, when a
// presence method existed at enrollment, the wrapped presence key blob.
type seRecord struct {
	Device   []byte `json:"device"`
	Presence []byte `json:"presence,omitempty"`
}

// NewSecureEnclaveStore returns the store, or an error naming why the Secure
// Enclave is unusable from this process (no SEP, or key creation refused).
// dir is where wrapped blobs live; empty means <state dir>/se.
func NewSecureEnclaveStore(dir string) (*SecureEnclaveStore, error) {
	if reason := seUnavailableReason(); reason != "" {
		return nil, fmt.Errorf("platform: %s", reason)
	}
	if dir == "" {
		base, err := stateDir()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(base, "se")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("platform: creating se key directory: %w", err)
	}
	return &SecureEnclaveStore{dir: dir}, nil
}

// seUnavailableReason probes by creating an ephemeral (non-persisted) Secure
// Enclave key and discarding it, which is the only real test of availability:
// it exercises the SEP, the code-signing state, and the keybag. Empty when
// usable.
func seUnavailableReason() string {
	var blob, pub unsafe.Pointer
	var bl, pl C.size_t
	var e C.totem_err
	if C.totem_se_create(0, &blob, &bl, &pub, &pl, &e) == 0 {
		return fmt.Sprintf("Secure Enclave unavailable: %s (%s %d)", C.GoString(&e.desc[0]), C.GoString(&e.domain[0]), int64(e.code))
	}
	C.free(blob)
	C.free(pub)
	return ""
}

// sePresenceAvailable reports whether a presence prompt (biometry or device
// password) can be evaluated right now, with the LAError code when not.
func sePresenceAvailable() (bool, int64) {
	var code C.long
	ok := C.totem_la_can(&code) != 0
	return ok, int64(code)
}

func seCandidate() Candidate {
	c := Candidate{Name: "secure-enclave", Level: spiffe.ProtectionHardware, Available: true}
	if r := seUnavailableReason(); r != "" {
		c.Available = false
		c.Reason = r
		return c
	}
	ok, code := sePresenceAvailable()
	c.Presence = ok
	switch {
	case !ok:
		c.Reason = fmt.Sprintf("unattested; no presence method (LAError %d): enrollment records presence none", code)
	case C.totem_la_biometry() != 0:
		c.Reason = "unattested (no third-party key attestation on Apple silicon); presence via Touch ID or password"
	default:
		c.Reason = "unattested (no third-party key attestation on Apple silicon); presence via device password (no biometry paired)"
	}
	return c
}

// ProtectionLevel is ProtectionHardware, queryable before any key exists.
func (s *SecureEnclaveStore) ProtectionLevel() spiffe.ProtectionLevel {
	return spiffe.ProtectionHardware
}

func (s *SecureEnclaveStore) path(label string) string {
	return filepath.Join(s.dir, label+".se")
}

func seCreate(presence bool) (blob []byte, pub *ecdsa.PublicKey, err error) {
	var cb, cp unsafe.Pointer
	var bl, pl C.size_t
	var e C.totem_err
	p := C.int(0)
	if presence {
		p = 1
	}
	if C.totem_se_create(p, &cb, &bl, &cp, &pl, &e) == 0 {
		return nil, nil, seError(&e)
	}
	blob = C.GoBytes(cb, C.int(bl))
	pubBytes := C.GoBytes(cp, C.int(pl))
	C.free(cb)
	C.free(cp)
	pub, err = parseX963(pubBytes)
	return blob, pub, err
}

func sePublic(blob []byte) (*ecdsa.PublicKey, error) {
	var cp unsafe.Pointer
	var pl C.size_t
	var e C.totem_err
	if C.totem_se_public(unsafe.Pointer(&blob[0]), C.size_t(len(blob)), &cp, &pl, &e) == 0 {
		return nil, seError(&e)
	}
	pubBytes := C.GoBytes(cp, C.int(pl))
	C.free(cp)
	return parseX963(pubBytes)
}

// parseX963 decodes an uncompressed P-256 point (0x04 || X || Y), validating
// it is on the curve.
func parseX963(b []byte) (*ecdsa.PublicKey, error) {
	if _, err := ecdh.P256().NewPublicKey(b); err != nil {
		return nil, fmt.Errorf("platform: Secure Enclave public key is not a valid P-256 point: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(b[1:33]),
		Y:     new(big.Int).SetBytes(b[33:65]),
	}, nil
}

// seErr is a CFError surfaced from the Security or LocalAuthentication
// frameworks, kept typed so the mapping to the contract errors is explicit.
type seErr struct {
	Domain string
	Code   int64
	Desc   string
}

func (e *seErr) Error() string {
	return fmt.Sprintf("platform: %s (%s %d)", e.Desc, e.Domain, e.Code)
}

func seError(e *C.totem_err) *seErr {
	return &seErr{Domain: C.GoString(&e.domain[0]), Code: int64(e.code), Desc: C.GoString(&e.desc[0])}
}

// Error codes the mapping keys on. LocalAuthentication codes are from
// LAError.h; OSStatus codes from SecBase.h.
const (
	laDomain             = "com.apple.LocalAuthentication"
	osStatusDomain       = "NSOSStatusErrorDomain"
	laAuthFailed         = -1
	laUserCancel         = -2
	laUserFallback       = -3
	laSystemCancel       = -4
	laPasscodeNotSet     = -5
	laBiometryLockout    = -8
	laAppCancel          = -9
	laNotInteractive     = -1004
	errSecUserCanceled   = -128
	errSecAuthFailed     = -25293
	errSecInteractionNot = -25308
)

// mapPresenceErr turns a framework error from a presence-gated signature into
// the contract's typed errors. Declined, failed, cancelled, or timed out is
// ErrPresenceDenied; no way to ask a human at all is ErrPresenceUnavailable.
func mapPresenceErr(err *seErr) error {
	switch err.Domain {
	case laDomain:
		switch err.Code {
		case laAuthFailed, laUserCancel, laUserFallback, laSystemCancel, laAppCancel, laBiometryLockout:
			return fmt.Errorf("%w: %v", ErrPresenceDenied, err)
		case laPasscodeNotSet, laNotInteractive:
			return fmt.Errorf("%w: %v", ErrPresenceUnavailable, err)
		}
	case osStatusDomain:
		switch err.Code {
		case errSecUserCanceled, errSecAuthFailed:
			return fmt.Errorf("%w: %v", ErrPresenceDenied, err)
		case errSecInteractionNot:
			return fmt.Errorf("%w: %v", ErrPresenceUnavailable, err)
		}
	}
	return err
}

// Generate creates the device key and, when a presence method exists on this
// Mac, the companion presence key, and writes their wrapped blobs to a 0600
// file created with O_EXCL (ErrKeyExists if label is taken). A Mac with no
// biometry and no password gets a device key only and is recorded as having
// no presence capability.
func (s *SecureEnclaveStore) Generate(ctx context.Context, label string) (Key, error) {
	if err := validateLabel(label); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(s.path(label)); err == nil {
		return nil, ErrKeyExists
	}
	devBlob, devPub, err := seCreate(false)
	if err != nil {
		return nil, fmt.Errorf("creating device key: %w", err)
	}
	rec := seRecord{Device: devBlob}
	var presPub *ecdsa.PublicKey
	if ok, _ := sePresenceAvailable(); ok {
		blob, pub, err := seCreate(true)
		if err != nil {
			return nil, fmt.Errorf("creating presence key: %w", err)
		}
		rec.Presence = blob
		presPub = pub
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.path(label), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, ErrKeyExists
		}
		return nil, fmt.Errorf("platform: creating se key record: %w", err)
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(s.path(label))
		return nil, fmt.Errorf("platform: writing se key record: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(s.path(label))
		return nil, err
	}
	return &seKey{rec: rec, pub: devPub, presPub: presPub}, nil
}

// Load returns the key under label or ErrKeyNotFound. The record file is
// checked for ownership and permissions, and each blob is re-imported into the
// Secure Enclave to recover its public key, which also proves the blob still
// belongs to this SEP.
func (s *SecureEnclaveStore) Load(ctx context.Context, label string) (Key, error) {
	if err := validateLabel(label); err != nil {
		return nil, err
	}
	p := s.path(label)
	if err := checkKeyFile(p); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrKeyNotFound
		}
		return nil, fmt.Errorf("platform: reading se key record: %w", err)
	}
	var rec seRecord
	if err := json.Unmarshal(raw, &rec); err != nil || len(rec.Device) == 0 {
		return nil, errors.New("platform: se key record is malformed")
	}
	pub, err := sePublic(rec.Device)
	if err != nil {
		return nil, fmt.Errorf("loading device key: %w", err)
	}
	k := &seKey{rec: rec, pub: pub}
	if len(rec.Presence) > 0 {
		if k.presPub, err = sePublic(rec.Presence); err != nil {
			return nil, fmt.Errorf("loading presence key: %w", err)
		}
	}
	return k, nil
}

// Delete removes the record. With no keychain copy, the wrapped blobs are the
// only handles to the keys; removing them destroys the keys.
func (s *SecureEnclaveStore) Delete(ctx context.Context, label string) error {
	if err := validateLabel(label); err != nil {
		return err
	}
	if err := os.Remove(s.path(label)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrKeyNotFound
		}
		return fmt.Errorf("platform: removing se key record: %w", err)
	}
	return nil
}

// seKey is a Secure Enclave device key plus optional companion presence key.
type seKey struct {
	rec     seRecord
	pub     *ecdsa.PublicKey
	presPub *ecdsa.PublicKey
}

// Public returns the device key's public half, the key the issuer enrolled and
// re-checks silently on renewal.
func (k *seKey) Public() crypto.PublicKey { return k.pub }

// PresencePublic returns the companion presence key's public half, or nil when
// this Mac had no presence method at enrollment.
func (k *seKey) PresencePublic() crypto.PublicKey {
	if k.presPub == nil {
		return nil
	}
	return k.presPub
}

// ProtectionLevel is ProtectionHardware.
func (k *seKey) ProtectionLevel() spiffe.ProtectionLevel { return spiffe.ProtectionHardware }

// Sign signs SHA-256(challenge) in the Secure Enclave, ASN.1 DER out.
//
// Required == false uses the device key under a LocalAuthentication context
// with interactionNotAllowed set: nothing can prompt, by construction.
//
// Required == true uses the companion presence key. The reason shown names
// the tool, target, device, and request code from prompt (see presenceReason). The Secure Enclave evaluates the
// key's user-presence access control and will not produce a signature until
// the human passes; decline, failure, or timeout is ErrPresenceDenied, no
// companion key or no way to prompt is ErrPresenceUnavailable.
func (k *seKey) Sign(ctx context.Context, challenge []byte, prompt Prompt) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(challenge)
	if !prompt.Required {
		sig, err := seSign(ctx, k.rec.Device, "renew the device identity", false, digest[:])
		if err != nil {
			return nil, fmt.Errorf("platform: device key signature: %w", err)
		}
		return sig, nil
	}
	if k.presPub == nil {
		return nil, ErrPresenceUnavailable
	}
	if prompt.Tool == "" || prompt.Target == "" || prompt.DeviceID == "" {
		return nil, ErrIncompletePrompt
	}
	reason := presenceReason(prompt)
	if _, has := ctx.Deadline(); !has {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultPresenceTimeout)
		defer cancel()
	}
	sig, err := seSign(ctx, k.rec.Presence, reason, true, digest[:])
	if err != nil {
		var se *seErr
		if errors.As(err, &se) {
			return nil, mapPresenceErr(se)
		}
		return nil, err
	}
	return sig, nil
}

// presenceReason is the LocalAuthentication reason text. macOS renders it as
// "totem is trying to <reason>", so it names the tool, the target, and the
// device, and for a presence:always target the request code the CLI printed,
// shown verbatim so the human can compare terminal and dialog.
func presenceReason(p Prompt) string {
	r := fmt.Sprintf("approve %s reaching %s from device %s", p.Tool, p.Target, p.DeviceID)
	if p.RequestCode != "" {
		r += fmt.Sprintf(" (request code %s)", p.RequestCode)
	}
	return r
}

// seSign runs one Secure Enclave signature under a fresh LAContext. If ctx
// ends first the context is invalidated, which makes the pending prompt fail
// with LAErrorAppCancel.
func seSign(ctx context.Context, blob []byte, reason string, interactive bool, digest []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, errors.New("platform: empty key blob")
	}
	creason := C.CString(reason)
	defer C.free(unsafe.Pointer(creason))
	inter := C.int(0)
	if interactive {
		inter = 1
	}
	la := C.totem_la_new(creason, inter)
	defer C.totem_la_free(la)

	type result struct {
		sig []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		var cs unsafe.Pointer
		var sl C.size_t
		var e C.totem_err
		if C.totem_se_sign(unsafe.Pointer(&blob[0]), C.size_t(len(blob)), la,
			unsafe.Pointer(&digest[0]), C.size_t(len(digest)), &cs, &sl, &e) == 0 {
			done <- result{err: seError(&e)}
			return
		}
		sig := C.GoBytes(cs, C.int(sl))
		C.free(cs)
		done <- result{sig: sig}
	}()
	select {
	case r := <-done:
		return r.sig, r.err
	case <-ctx.Done():
		C.totem_la_invalidate(la)
		<-done // the SEP call returns once the context is invalidated
		return nil, fmt.Errorf("%w: %v", ErrPresenceDenied, ctx.Err())
	}
}
