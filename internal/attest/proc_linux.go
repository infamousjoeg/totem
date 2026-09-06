//go:build linux

package attest

// Linux process facts from SO_PEERCRED and procfs. There is no kernel code
// signing here, so the anchor for a catalog binary is the pinned hash alone
// (Options.Pins) and the "OS-signed shell" rule degrades to "a shell the OS
// installed at a root-owned, non-writable path". The running executable is
// hashed through /proc/<pid>/exe, which opens the running inode itself, so a
// binary replaced on disk after exec is seen for what is actually running.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type linuxSystem struct{}

func init() {
	defaultSystem = linuxSystem{}
}

func (linuxSystem) peer(conn *net.UnixConn) (peerCred, error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return peerCred{}, err
	}
	var pc peerCred
	var inner error
	err = rc.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			inner = fmt.Errorf("attest: SO_PEERCRED: %w", err)
			return
		}
		pc = peerCred{pid: cred.Pid, uid: cred.Uid, gid: cred.Gid}
	})
	if err != nil {
		return peerCred{}, err
	}
	if inner != nil {
		return peerCred{}, inner
	}
	if pc.pid <= 0 {
		return peerCred{}, errors.New("attest: kernel reported no peer pid")
	}
	return pc, nil
}

// clockTicksPerSecond is USER_HZ, which is 100 on every Linux ABI Go
// supports. It only scales the start time; the reuse check compares the raw
// value against itself.
const clockTicksPerSecond = 100

var bootTime struct {
	t   time.Time
	err error
	set bool
}

func readBootTime() (time.Time, error) {
	if bootTime.set {
		return bootTime.t, bootTime.err
	}
	bootTime.set = true
	f, err := os.Open("/proc/stat")
	if err != nil {
		bootTime.err = err
		return time.Time{}, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if strings.HasPrefix(s.Text(), "btime ") {
			v, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(s.Text(), "btime ")), 10, 64)
			if err != nil {
				bootTime.err = err
				return time.Time{}, err
			}
			bootTime.t = time.Unix(v, 0)
			return bootTime.t, nil
		}
	}
	bootTime.err = errors.New("attest: no btime in /proc/stat")
	return time.Time{}, bootTime.err
}

func (linuxSystem) process(pid int32) (*process, error) {
	dir := fmt.Sprintf("/proc/%d", pid)
	stat, err := os.ReadFile(dir + "/stat")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("attest: pid %d: %w", pid, errProcessGone)
		}
		return nil, err
	}
	// pid (comm) state ppid ... ; comm may contain spaces and parens, so
	// split after the last ')'.
	close := bytes.LastIndexByte(stat, ')')
	if close < 0 {
		return nil, fmt.Errorf("attest: malformed %s/stat", dir)
	}
	fields := strings.Fields(string(stat[close+1:]))
	if len(fields) < 20 {
		return nil, fmt.Errorf("attest: short %s/stat", dir)
	}
	ppid, err := strconv.ParseInt(fields[1], 10, 32)
	if err != nil {
		return nil, err
	}
	ticks, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil {
		return nil, err
	}
	boot, err := readBootTime()
	if err != nil {
		return nil, err
	}
	p := &process{pid: pid, ppid: int32(ppid)}
	p.startTime = boot.Add(time.Duration(ticks) * time.Second / clockTicksPerSecond)

	status, err := os.ReadFile(dir + "/status")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") || strings.HasPrefix(line, "Gid:") {
			f := strings.Fields(line)
			if len(f) < 3 {
				return nil, fmt.Errorf("attest: malformed %s/status", dir)
			}
			v, err := strconv.ParseUint(f[2], 10, 32) // effective id
			if err != nil {
				return nil, err
			}
			if line[0] == 'U' {
				p.uid = uint32(v)
			} else {
				p.gid = uint32(v)
			}
		}
	}
	exe, err := os.Readlink(dir + "/exe")
	if err != nil {
		return nil, fmt.Errorf("attest: readlink %s/exe: %w", dir, err)
	}
	if strings.HasSuffix(exe, " (deleted)") {
		return nil, fmt.Errorf("attest: pid %d executable %s was deleted after exec", pid, strings.TrimSuffix(exe, " (deleted)"))
	}
	p.exePath = exe
	return p, nil
}

func (linuxSystem) codeSign(pid int32) (*kernelCodeSign, error) {
	return &kernelCodeSign{present: false}, nil
}

func (linuxSystem) openExecutable(p *process) (*os.File, error) {
	return os.Open(fmt.Sprintf("/proc/%d/exe", p.pid))
}

func (linuxSystem) executable() (string, error) {
	return os.Executable()
}

func (linuxSystem) uid() uint32 {
	return uint32(os.Getuid())
}
