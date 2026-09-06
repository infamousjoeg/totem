//go:build unix

package summon

import (
	"os/exec"
	"syscall"
)

// setProcessGroup puts the provider in its own process group so a provider
// that spawned children can be killed as a unit. Killing only the provider
// would leave a child holding the pipe, and a resolve waiting on it.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup kills the provider and everything it started when the
// timeout fires.
func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err == nil {
		return nil
	}
	return cmd.Process.Kill()
}
