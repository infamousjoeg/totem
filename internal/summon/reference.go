package summon

import (
	"fmt"
	"strings"
)

// MaxReferenceLen bounds a reference name. A reference is operator-authored
// config, not user input, so the bound is generous; it exists so a corrupted
// config cannot hand a provider a megabyte of argv.
const MaxReferenceLen = 256

// validateReference enforces the strict pattern from docs/totem-design.md
// "Secrets": "strict reference name validation", applied BEFORE the reference
// becomes argv.
//
// A reference is one or more '/'-separated segments of ASCII letters, digits,
// '.', '_' and '-', and it must start with a letter or digit. The leading
// character rule is the load-bearing one: a reference beginning with '-' would
// reach the provider as a flag rather than a name, so it is refused before
// exec, not sanitized after. '.' and '..' are not legal segments, which is
// also what keeps a file-provider reference underneath its directory.
func validateReference(ref Reference) error {
	s := string(ref)
	if s == "" {
		return fmt.Errorf("%w: reference is empty", ErrBadReference)
	}
	if len(s) > MaxReferenceLen {
		return fmt.Errorf("%w: reference is %d bytes, over the %d-byte limit", ErrBadReference, len(s), MaxReferenceLen)
	}
	if !isRefAlnum(s[0]) {
		return fmt.Errorf("%w: reference %q must start with a letter or digit, so it can never be read as a command-line flag", ErrBadReference, s)
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !isRefAlnum(c) && !strings.ContainsRune("._-/", rune(c)) {
			return fmt.Errorf("%w: reference %q contains the illegal byte %#02x at offset %d", ErrBadReference, s, c, i)
		}
	}
	if strings.HasSuffix(s, "/") {
		return fmt.Errorf("%w: reference %q ends with a separator", ErrBadReference, s)
	}
	if strings.Contains(s, "//") {
		return fmt.Errorf("%w: reference %q has an empty segment", ErrBadReference, s)
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("%w: reference %q has a %q segment", ErrBadReference, s, seg)
		}
	}
	return nil
}

// isRefAlnum reports whether c is an ASCII letter or digit. Bytes outside
// ASCII are rejected by construction: there is no case in which a secret
// reference needs one, and a homoglyph in a reference is a way to point the
// issuer at a different secret than the config appears to name.
func isRefAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
