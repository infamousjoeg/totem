package summon

import (
	"io"
	"os"
	"testing"
)

// TestMain points the unsilenceable warning at io.Discard for tests that are
// not about it, so the suite's output stays readable. This is test hygiene and
// not a silencer: production has no such switch, warnSink is unexported and
// only reachable from the test binary, and
// TestFileProviderWarnsOnEveryStartAndCannotBeSilenced puts a real sink back
// and asserts the warning appears on every start.
func TestMain(m *testing.M) {
	restore := setWarnSink(io.Discard)
	code := m.Run()
	restore()
	os.Exit(code)
}
