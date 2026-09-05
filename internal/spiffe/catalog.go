package spiffe

// Catalog is the shipped tool catalog. Tool names come from a shipped catalog
// of {name, team_id, signing_id, expected_paths}. Default deny: a tool absent
// from the catalog gets no identity.
//
// The claude row is verified: the Claude Code binary is a native Mach-O arm64
// (both the npm and native installs), signed by Anthropic PBC (Team ID
// Q6L2SF6YDW, identifier com.anthropic.claude-code), so it is attestable by the
// pin + Team ID + parent-walk model rather than excluded as interpreter-wrapped.
var Catalog = []CatalogEntry{
	{
		Name:      "claude",
		TeamID:    "Q6L2SF6YDW",
		SigningID: "com.anthropic.claude-code",
		ExpectedPaths: []string{
			"~/.local/share/claude/versions/*",
			"/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe",
		},
	},
	// aws (Roles Anywhere bridge) and gh/git (GitHub bridge) rows land as those
	// bridges are built. See docs/totem-design.md, "Bridges".
}
