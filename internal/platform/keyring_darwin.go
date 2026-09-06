//go:build darwin && cgo

package platform

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

static const char *totemKeyringService = "totem device key";

static CFMutableDictionaryRef totem_kr_query(const char *account) {
	CFMutableDictionaryRef q = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFStringRef svc = CFStringCreateWithCString(kCFAllocatorDefault, totemKeyringService, kCFStringEncodingUTF8);
	CFStringRef acc = CFStringCreateWithCString(kCFAllocatorDefault, account, kCFStringEncodingUTF8);
	CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(q, kSecAttrService, svc);
	CFDictionarySetValue(q, kSecAttrAccount, acc);
	CFRelease(svc);
	CFRelease(acc);
	return q;
}

// totem_kr_add stores data as a generic-password item in the login keychain.
// errSecDuplicateItem when the account already exists.
static OSStatus totem_kr_add(const char *account, const void *data, size_t len) {
	CFMutableDictionaryRef q = totem_kr_query(account);
	CFDataRef d = CFDataCreate(kCFAllocatorDefault, data, (CFIndex)len);
	CFDictionarySetValue(q, kSecValueData, d);
	CFStringRef label = CFStringCreateWithCString(kCFAllocatorDefault, "totem", kCFStringEncodingUTF8);
	CFDictionarySetValue(q, kSecAttrLabel, label);
	OSStatus st = SecItemAdd(q, NULL);
	CFRelease(label);
	CFRelease(d);
	CFRelease(q);
	return st;
}

// totem_kr_get copies the item's data into a malloc'd buffer the caller frees.
static OSStatus totem_kr_get(const char *account, void **out, size_t *outlen) {
	CFMutableDictionaryRef q = totem_kr_query(account);
	CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
	CFTypeRef result = NULL;
	OSStatus st = SecItemCopyMatching(q, &result);
	CFRelease(q);
	if (st != errSecSuccess) return st;
	CFDataRef d = (CFDataRef)result;
	*outlen = (size_t)CFDataGetLength(d);
	*out = malloc(*outlen);
	memcpy(*out, CFDataGetBytePtr(d), *outlen);
	CFRelease(result);
	return errSecSuccess;
}

static OSStatus totem_kr_delete(const char *account) {
	CFMutableDictionaryRef q = totem_kr_query(account);
	OSStatus st = SecItemDelete(q);
	CFRelease(q);
	return st;
}

// totem_kr_probe checks the default keychain is reachable and unlocked by
// looking up an account that does not exist: errSecItemNotFound is the
// healthy answer; errSecNotAvailable / errSecInteractionNotAllowed mean no
// usable keychain (a launchd daemon with no login keychain, for example).
static OSStatus totem_kr_probe(void) {
	CFMutableDictionaryRef q = totem_kr_query("totem-keyring-probe-does-not-exist");
	CFDictionarySetValue(q, kSecReturnAttributes, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
	CFTypeRef result = NULL;
	OSStatus st = SecItemCopyMatching(q, &result);
	CFRelease(q);
	if (result) CFRelease(result);
	return st;
}
*/
import "C"

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"unsafe"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

// KeychainStore is the macOS keyring level: a P-256 key generated in-process
// and stored as a generic-password item in the user's login keychain. It is
// "keyring-backed software key when no hardware exists; never refused, always
// recorded": the keychain encrypts it at rest, but the item carries the default
// access (no kSecAttrAccessControl, no access group, which would need Developer
// ID signing), so it is readable by any process running as this user while the
// login keychain is unlocked, and the private key is in process memory during
// Sign. The level is ProtectionKeyring, not hardware, and there is no presence
// capability; the design makes no theft-elimination claim below hardware.
type KeychainStore struct{}

// NewKeychainStore returns the keychain store, or an error when this process
// has no usable login keychain (for example a system daemon).
func NewKeychainStore() (*KeychainStore, error) {
	if reason := keychainUnavailableReason(); reason != "" {
		return nil, fmt.Errorf("platform: %s", reason)
	}
	return &KeychainStore{}, nil
}

// keychainUnavailableReason is empty when the login keychain is reachable.
func keychainUnavailableReason() string {
	switch st := C.totem_kr_probe(); st {
	case C.errSecItemNotFound, C.errSecSuccess:
		return ""
	default:
		return fmt.Sprintf("login keychain unavailable (OSStatus %d)", int32(st))
	}
}

// ProtectionLevel is ProtectionKeyring, queryable before any key exists.
func (s *KeychainStore) ProtectionLevel() spiffe.ProtectionLevel {
	return spiffe.ProtectionKeyring
}

// Generate creates a P-256 key and adds it to the login keychain under label.
// SecItemAdd refuses a duplicate atomically, which maps to ErrKeyExists.
func (s *KeychainStore) Generate(ctx context.Context, label string) (Key, error) {
	if err := validateLabel(label); err != nil {
		return nil, err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("platform: generating key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("platform: encoding key: %w", err)
	}
	cl := C.CString(label)
	defer C.free(unsafe.Pointer(cl))
	st := C.totem_kr_add(cl, unsafe.Pointer(&der[0]), C.size_t(len(der)))
	switch st {
	case C.errSecSuccess:
	case C.errSecDuplicateItem:
		return nil, ErrKeyExists
	default:
		return nil, fmt.Errorf("platform: keychain SecItemAdd failed (OSStatus %d)", int32(st))
	}
	return &softwareKey{priv: priv, level: spiffe.ProtectionKeyring}, nil
}

// Load reads the key under label from the login keychain, or ErrKeyNotFound.
func (s *KeychainStore) Load(ctx context.Context, label string) (Key, error) {
	if err := validateLabel(label); err != nil {
		return nil, err
	}
	cl := C.CString(label)
	defer C.free(unsafe.Pointer(cl))
	var out unsafe.Pointer
	var n C.size_t
	st := C.totem_kr_get(cl, &out, &n)
	switch st {
	case C.errSecSuccess:
	case C.errSecItemNotFound:
		return nil, ErrKeyNotFound
	default:
		return nil, fmt.Errorf("platform: keychain SecItemCopyMatching failed (OSStatus %d)", int32(st))
	}
	der := C.GoBytes(out, C.int(n))
	C.free(out)
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("platform: parsing keychain item: %w", err)
	}
	priv, ok := k.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("platform: keychain item is not an ECDSA P-256 key")
	}
	return &softwareKey{priv: priv, level: spiffe.ProtectionKeyring}, nil
}

// Delete removes the keychain item under label, or ErrKeyNotFound.
func (s *KeychainStore) Delete(ctx context.Context, label string) error {
	if err := validateLabel(label); err != nil {
		return err
	}
	cl := C.CString(label)
	defer C.free(unsafe.Pointer(cl))
	switch st := C.totem_kr_delete(cl); st {
	case C.errSecSuccess:
		return nil
	case C.errSecItemNotFound:
		return ErrKeyNotFound
	default:
		return fmt.Errorf("platform: keychain SecItemDelete failed (OSStatus %d)", int32(st))
	}
}

func keychainCandidate() Candidate {
	c := Candidate{Name: "keyring", Level: spiffe.ProtectionKeyring, Available: true}
	if r := keychainUnavailableReason(); r != "" {
		c.Available = false
		c.Reason = r
	}
	return c
}
