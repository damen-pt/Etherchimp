//go:build linux

package daemon

import "syscall"

// dupFD redirects newfd to oldfd. Linux arm64 (and riscv64) never got the
// dup2 syscall, so all Linux builds use dup3, which every arch has.
func dupFD(oldfd, newfd int) error {
	return syscall.Dup3(oldfd, newfd, 0)
}
