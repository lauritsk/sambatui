//go:build linux || darwin || freebsd || openbsd || netbsd

// Package privatefile opens private, regular, owner-only files without following
// symlinks or blocking on attacker-controlled FIFOs.
package privatefile

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func Open(path string) (*os.File, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	st, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	var info unix.Stat_t
	if e = unix.Fstat(fd, &info); e != nil {
		f.Close()
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 || info.Uid != uint32(os.Getuid()) {
		f.Close()
		return nil, errors.New("credential/state file must be a regular non-symlink file owned by current user with mode 0600")
	}
	return f, nil
}
