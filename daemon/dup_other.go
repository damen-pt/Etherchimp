//go:build !linux

package daemon

import "syscall"

// dupFD redirects newfd to oldfd (darwin/BSD: plain dup2).
func dupFD(oldfd, newfd int) error {
	return syscall.Dup2(oldfd, newfd)
}
