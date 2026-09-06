//go:build !unix

package summon

import "os/exec"

// setProcessGroup has no process-group equivalent on this platform.
func setProcessGroup(*exec.Cmd) {}

// killProcessGroup falls back to killing the provider alone.
func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
