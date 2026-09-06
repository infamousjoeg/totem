//go:build unix

package summon

import "syscall"

// makeFIFO creates a named pipe, so the "neither a directory nor a regular
// file" refusal is exercised against a real inode type.
func makeFIFO(p string) error { return syscall.Mkfifo(p, 0o644) }
