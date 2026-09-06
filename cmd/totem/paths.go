package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// Everything totem keeps on the laptop lives under ~/.totem at 0700. Per
// docs/totem-design.md "Agent (laptop)", that is the enrollment record and the
// pinned issuer certificate, plus the local log. SVIDs are memory only and
// presence sessions live on the issuer, so neither is ever written here.

// homeDir resolves the user's home directory, falling back to the account
// database when HOME is unset (a launchd agent's environment can be sparse).
func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return u.HomeDir
	}
	return "."
}

// totemDir is ~/.totem.
func totemDir() string { return filepath.Join(homeDir(), ".totem") }

// expandHome turns a leading ~ into the home directory, which is how the
// constants in internal/errors are written.
func expandHome(p string) string {
	if p == "~" {
		return homeDir()
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(homeDir(), p[2:])
	}
	return p
}
