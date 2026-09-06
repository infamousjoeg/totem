//go:build darwin

package attest

// macOS process facts, straight from the kernel with raw syscalls: no cgo, no
// libproc, no shelling out. Three interfaces carry everything the attestor
// needs:
//
//   - getsockopt(SOL_LOCAL, LOCAL_PEERCRED / LOCAL_PEERPID / LOCAL_PEERTOKEN)
//     on the accepted socket: uid, gid, pid, and the audit token, whose
//     pidversion is the kernel's own pid-reuse counter captured at connect
//     time.
//   - proc_info(PROC_INFO_CALL_PIDINFO): start time and ppid (PROC_PIDTBSDINFO),
//     the unique process id, parent unique id and pidversion
//     (PROC_PIDUNIQIDENTIFIERINFO), and the executable's path resolved from
//     its vnode (PROC_PIDPATHINFO).
//   - csops: the kernel's code-signing status flags, the cdhash of the code
//     actually running in the process, its signing identifier and Team ID.
//
// The csops facts are the load-bearing ones. proc_pidpath keeps returning the
// original path after the running binary has been renamed over (verified on
// macOS 26), so the file at the path can differ from the code in the process;
// the attestor refuses unless the on-disk CodeDirectory has exactly the cdhash
// the kernel reports for the running process.

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	solLocal       = 0
	localPeerCred  = 0x001
	localPeerPID   = 0x002
	localPeerToken = 0x006

	procInfoCallPIDInfo       = 2
	procPIDTBSDInfo           = 3
	procPIDPathInfo           = 11
	procPIDUniqIdentifierInfo = 17
	procPIDPathInfoMaxSize    = 4 * 1024
	procBSDInfoSize           = 136
	procUniqIdentifierSize    = 64

	csOpsStatus   = 0
	csOpsCDHash   = 5
	csOpsIdentity = 11
	csOpsTeamID   = 14
)

// darwinSystem is the macOS implementation of system.
type darwinSystem struct{}

func init() {
	defaultSystem = darwinSystem{}
}

func getsockopt(fd uintptr, level, name int, buf []byte) (int, error) {
	l := uint32(len(buf))
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, uintptr(level), uintptr(name), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&l)), 0)
	if e != 0 {
		return 0, e
	}
	return int(l), nil
}

// peer reads the kernel's record of who connected. LOCAL_PEERPID and the
// audit token are captured by the kernel at connect time, so they describe
// the process that connected even if it has since exec'd or exited.
func (darwinSystem) peer(conn *net.UnixConn) (peerCred, error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return peerCred{}, err
	}
	var pc peerCred
	var inner error
	err = rc.Control(func(fd uintptr) {
		// struct xucred: u_int cr_version; uid_t cr_uid; short cr_ngroups; gid_t cr_groups[16]
		cred := make([]byte, 76)
		n, err := getsockopt(fd, solLocal, localPeerCred, cred)
		if err != nil {
			inner = fmt.Errorf("attest: LOCAL_PEERCRED: %w", err)
			return
		}
		if n < 16 || *(*uint32)(unsafe.Pointer(&cred[0])) != 0 {
			inner = errors.New("attest: LOCAL_PEERCRED returned an unknown xucred layout")
			return
		}
		pc.uid = *(*uint32)(unsafe.Pointer(&cred[4]))
		if *(*int16)(unsafe.Pointer(&cred[8])) > 0 {
			pc.gid = *(*uint32)(unsafe.Pointer(&cred[12]))
		}
		pidBuf := make([]byte, 4)
		if _, err := getsockopt(fd, solLocal, localPeerPID, pidBuf); err != nil {
			inner = fmt.Errorf("attest: LOCAL_PEERPID: %w", err)
			return
		}
		pc.pid = *(*int32)(unsafe.Pointer(&pidBuf[0]))
		// audit_token_t: val[8] = auid, euid, egid, ruid, rgid, pid, asid, pidversion
		tok := make([]byte, 32)
		if _, err := getsockopt(fd, solLocal, localPeerToken, tok); err != nil {
			inner = fmt.Errorf("attest: LOCAL_PEERTOKEN: %w", err)
			return
		}
		t := (*[8]uint32)(unsafe.Pointer(&tok[0]))
		if int32(t[5]) != pc.pid {
			inner = fmt.Errorf("attest: audit token pid %d disagrees with LOCAL_PEERPID %d", t[5], pc.pid)
			return
		}
		if t[1] != pc.uid {
			inner = fmt.Errorf("attest: audit token euid %d disagrees with LOCAL_PEERCRED uid %d", t[1], pc.uid)
			return
		}
		pc.pidVersion = int32(t[7])
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

func procInfo(pid int32, flavor int, buf []byte) (int, error) {
	r1, _, e := syscall.Syscall6(syscall.SYS_PROC_INFO, procInfoCallPIDInfo, uintptr(pid), uintptr(flavor), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if e != 0 {
		return 0, e
	}
	return int(r1), nil
}

// process reads the facts about pid that the walk depends on. Every field
// comes from the kernel; nothing is read from the process's own memory or
// argv.
func (darwinSystem) process(pid int32) (*process, error) {
	bsd := make([]byte, procBSDInfoSize)
	n, err := procInfo(pid, procPIDTBSDInfo, bsd)
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil, fmt.Errorf("attest: pid %d: %w", pid, errProcessGone)
		}
		return nil, fmt.Errorf("attest: proc_info(PROC_PIDTBSDINFO) pid %d: %w", pid, err)
	}
	if n < procBSDInfoSize {
		return nil, fmt.Errorf("attest: proc_info(PROC_PIDTBSDINFO) returned %d bytes", n)
	}
	p := &process{pid: pid}
	if got := *(*uint32)(unsafe.Pointer(&bsd[12])); int32(got) != pid {
		return nil, fmt.Errorf("attest: proc_info returned pid %d for pid %d", got, pid)
	}
	p.ppid = int32(*(*uint32)(unsafe.Pointer(&bsd[16])))
	p.uid = *(*uint32)(unsafe.Pointer(&bsd[20]))
	p.gid = *(*uint32)(unsafe.Pointer(&bsd[24]))
	sec := *(*uint64)(unsafe.Pointer(&bsd[120]))
	usec := *(*uint64)(unsafe.Pointer(&bsd[128]))
	p.startTime = time.Unix(int64(sec), int64(usec)*1000)

	uq := make([]byte, procUniqIdentifierSize)
	if _, err := procInfo(pid, procPIDUniqIdentifierInfo, uq); err != nil {
		return nil, fmt.Errorf("attest: proc_info(PROC_PIDUNIQIDENTIFIERINFO) pid %d: %w", pid, err)
	}
	// struct proc_uniqidentifierinfo: uuid[16], uint64 p_uniqueid, uint64 p_puniqueid, int32 p_idversion, ...
	p.uniqueID = *(*uint64)(unsafe.Pointer(&uq[16]))
	p.parentUniqueID = *(*uint64)(unsafe.Pointer(&uq[24]))
	p.pidVersion = *(*int32)(unsafe.Pointer(&uq[32]))

	path := make([]byte, procPIDPathInfoMaxSize)
	if _, err := procInfo(pid, procPIDPathInfo, path); err != nil {
		return nil, fmt.Errorf("attest: proc_pidpath pid %d: %w", pid, err)
	}
	// The buffer past the terminating NUL is not cleared by the kernel.
	if i := bytes.IndexByte(path, 0); i >= 0 {
		path = path[:i]
	}
	p.exePath = string(path)
	if p.exePath == "" {
		return nil, fmt.Errorf("attest: proc_pidpath pid %d returned an empty path", pid)
	}
	return p, nil
}

func csops(pid int32, op int, buf []byte) error {
	_, _, e := syscall.Syscall6(syscall.SYS_CSOPS, uintptr(pid), uintptr(op), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	if e != 0 {
		return e
	}
	return nil
}

// codeSign asks the kernel what it knows about the code running in pid. The
// cdhash is the anchor: it is the hash of the CodeDirectory the kernel loaded
// at exec, and it is what the on-disk signature must match.
func (darwinSystem) codeSign(pid int32) (*kernelCodeSign, error) {
	st := make([]byte, 4)
	if err := csops(pid, csOpsStatus, st); err != nil {
		return nil, fmt.Errorf("attest: csops(CS_OPS_STATUS) pid %d: %w", pid, err)
	}
	k := &kernelCodeSign{present: true, flags: *(*uint32)(unsafe.Pointer(&st[0]))}
	cd := make([]byte, cdHashLen)
	if err := csops(pid, csOpsCDHash, cd); err != nil {
		return nil, fmt.Errorf("attest: csops(CS_OPS_CDHASH) pid %d: %w", pid, err)
	}
	k.cdHash = cd
	// CS_OPS_IDENTITY and CS_OPS_TEAMID return a blob: 8-byte header then the
	// NUL-terminated string. ENOENT from TEAMID means the binary has none.
	id := make([]byte, 1024)
	if err := csops(pid, csOpsIdentity, id); err != nil {
		return nil, fmt.Errorf("attest: csops(CS_OPS_IDENTITY) pid %d: %w", pid, err)
	}
	k.identity = cStringAt(id, 8)
	team := make([]byte, 1024)
	if err := csops(pid, csOpsTeamID, team); err != nil {
		if !errors.Is(err, syscall.ENOENT) {
			return nil, fmt.Errorf("attest: csops(CS_OPS_TEAMID) pid %d: %w", pid, err)
		}
	} else {
		k.teamID = cStringAt(team, 8)
	}
	return k, nil
}

// cStringAt returns the NUL-terminated string starting at off.
func cStringAt(b []byte, off int) string {
	if off >= len(b) {
		return ""
	}
	b = b[off:]
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// openExecutable opens the path the kernel resolved for the process's text
// vnode. The file there may not be the running code (see the file comment);
// the caller's cdhash cross-check is what makes this safe.
func (darwinSystem) openExecutable(p *process) (*os.File, error) {
	return os.Open(p.exePath)
}

func (darwinSystem) executable() (string, error) {
	return os.Executable()
}

func (darwinSystem) uid() uint32 {
	return uint32(os.Getuid())
}
