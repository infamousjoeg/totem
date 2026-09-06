package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Decision 2: pin-on-init is the default anchor everywhere. `totem init`
// records each tool's hash, and on change the agent refuses the tool until
// `totem trust <tool>` is run and shows old and new hash.
//
// `totem init` is step 3, so nothing writes this file yet. It is defined here
// because attest.New takes the pin table as a required parameter precisely so
// that a caller passing none is making a visible decision rather than getting
// the weaker anchor silently, and the agent needs somewhere to read them from
// the moment init starts writing them.

// PinsPath is ~/.totem/pins.json: a flat map of catalog tool name to the hex
// SHA-256 the binary was pinned to.
func PinsPath() string { return filepath.Join(totemDir(), "pins.json") }

// LoadPins reads the pin table. A missing file returns nil, which attest
// documents as "use the chain-verified Team ID plus signing identifier as the
// anchor instead, and record the observed hash rather than enforcing it". On
// Linux that means a catalog match without a pin gets no identity, which is the
// correct, loud outcome for a device that has not run init.
func LoadPins() (map[string]string, error) {
	data, err := os.ReadFile(PinsPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var pins map[string]string
	if err := json.Unmarshal(data, &pins); err != nil {
		return nil, fmt.Errorf("the record of pinned programs at %s cannot be read: %w", PinsPath(), err)
	}
	return pins, nil
}

// SavePins writes the pin table at 0600. It exists for `totem init` and
// `totem trust <tool>` to call when they arrive; nothing in this build writes
// pins on its own, because a pin totem invented is not a pin.
func SavePins(pins map[string]string) error {
	if err := os.MkdirAll(totemDir(), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(pins, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(PinsPath(), append(data, '\n'), 0o600)
}
