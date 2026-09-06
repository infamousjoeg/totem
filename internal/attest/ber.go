package attest

// BER to DER normalisation. Apple's Security framework emits the CMS blob of
// a code signature with BER indefinite-length encodings for the outer
// containers; Go's encoding/asn1 accepts only DER. RFC 5652 defines the
// signed attributes' signature over their DER encoding, so re-encoding to DER
// before parsing is both necessary and the correct thing to verify against.
// Only structure is rewritten: tags and primitive contents are copied
// verbatim.

import (
	"errors"
)

var errBER = errors.New("attest: malformed BER")

// berToDER re-encodes b so every element has a definite length and every
// constructed string is merged into one primitive. It returns b unchanged
// when it is already DER.
func berToDER(b []byte) ([]byte, error) {
	out, rest, err := berElement(b)
	if err != nil {
		return nil, err
	}
	// Trailing zero padding after the outermost element is tolerated (blob
	// wrappers are padded); anything else is an error.
	for _, c := range rest {
		if c != 0 {
			return nil, errBER
		}
	}
	return out, nil
}

// berElement encodes one element from the front of b and returns the DER
// form and the remaining input.
func berElement(b []byte) (der []byte, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, errBER
	}
	// Identifier octets: class/constructed/tag, with high-tag-number form.
	idLen := 1
	if b[0]&0x1f == 0x1f {
		for {
			if idLen >= len(b) {
				return nil, nil, errBER
			}
			idLen++
			if b[idLen-1]&0x80 == 0 {
				break
			}
		}
	}
	ident := b[:idLen]
	constructed := b[0]&0x20 != 0
	universalTag := -1
	if b[0]&0xc0 == 0 && b[0]&0x1f != 0x1f {
		universalTag = int(b[0] & 0x1f)
	}
	if idLen >= len(b) {
		return nil, nil, errBER
	}
	lb := b[idLen]
	pos := idLen + 1
	var contents []byte
	var indefinite bool
	switch {
	case lb == 0x80:
		if !constructed {
			return nil, nil, errBER
		}
		indefinite = true
	case lb&0x80 == 0:
		n := int(lb)
		if pos+n > len(b) {
			return nil, nil, errBER
		}
		contents = b[pos : pos+n]
		rest = b[pos+n:]
	default:
		nbytes := int(lb & 0x7f)
		if nbytes == 0 || nbytes > 4 || pos+nbytes > len(b) {
			return nil, nil, errBER
		}
		n := 0
		for i := 0; i < nbytes; i++ {
			n = n<<8 | int(b[pos+i])
		}
		pos += nbytes
		if n < 0 || pos+n > len(b) {
			return nil, nil, errBER
		}
		contents = b[pos : pos+n]
		rest = b[pos+n:]
	}

	if !constructed {
		return encodeDER(ident, contents), rest, nil
	}

	// Constructed: re-encode children. For an indefinite length, children run
	// until the end-of-contents marker.
	var children [][]byte
	var body []byte
	if indefinite {
		body = b[pos:]
	} else {
		body = contents
	}
	for {
		if indefinite {
			if len(body) < 2 {
				return nil, nil, errBER
			}
			if body[0] == 0 && body[1] == 0 {
				rest = body[2:]
				break
			}
		} else if len(body) == 0 {
			break
		}
		child, more, err := berElement(body)
		if err != nil {
			return nil, nil, err
		}
		children = append(children, child)
		body = more
	}

	// A constructed string type (OCTET STRING, BIT STRING is not merged,
	// UTF8String etc.) collapses to one primitive with the concatenated
	// contents, which is what DER requires.
	if universalTag == 4 || universalTag == 12 || universalTag == 19 || universalTag == 22 {
		var merged []byte
		for _, c := range children {
			_, cc, err := splitDER(c)
			if err != nil {
				return nil, nil, err
			}
			merged = append(merged, cc...)
		}
		return encodeDER([]byte{ident[0] &^ 0x20}, merged), rest, nil
	}
	var joined []byte
	for _, c := range children {
		joined = append(joined, c...)
	}
	return encodeDER(ident, joined), rest, nil
}

// splitDER returns the identifier and contents of one DER element.
func splitDER(b []byte) (ident, contents []byte, err error) {
	idLen := 1
	if b[0]&0x1f == 0x1f {
		for idLen < len(b) {
			idLen++
			if b[idLen-1]&0x80 == 0 {
				break
			}
		}
	}
	if idLen >= len(b) {
		return nil, nil, errBER
	}
	lb := b[idLen]
	pos := idLen + 1
	n := int(lb)
	if lb&0x80 != 0 {
		nbytes := int(lb & 0x7f)
		if pos+nbytes > len(b) {
			return nil, nil, errBER
		}
		n = 0
		for i := 0; i < nbytes; i++ {
			n = n<<8 | int(b[pos+i])
		}
		pos += nbytes
	}
	if pos+n > len(b) {
		return nil, nil, errBER
	}
	return b[:idLen], b[pos : pos+n], nil
}

// encodeDER writes ident, a definite length, and contents.
func encodeDER(ident, contents []byte) []byte {
	n := len(contents)
	out := make([]byte, 0, len(ident)+5+n)
	out = append(out, ident...)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	case n < 0x10000:
		out = append(out, 0x82, byte(n>>8), byte(n))
	case n < 0x1000000:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	default:
		out = append(out, 0x84, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, contents...)
}
