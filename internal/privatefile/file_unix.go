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
	descriptor, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	metadata, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	var info unix.Stat_t
	if err = unix.Fstat(descriptor, &info); err != nil {
		file.Close()
		return nil, err
	}
	if !metadata.Mode().IsRegular() || metadata.Mode().Perm()&0o077 != 0 ||
		info.Uid != uint32(os.Getuid()) {
		file.Close()
		return nil, errors.New(
			"credential/state file must be a regular non-symlink file " +
				"owned by current user with mode 0600",
		)
	}
	return file, nil
}
