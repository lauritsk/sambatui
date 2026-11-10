//go:build linux || darwin || freebsd || openbsd || netbsd

// Package configfile reads bounded public configuration files. Unlike credential
// files, these may be symlinked or world-readable, but must not be devices/FIFOs.
package configfile

import (
	"errors"
	"io"
	"os"

	"github.com/lauritsk/sambatui/internal/invariant"
	"golang.org/x/sys/unix"
)

func Read(path string, sizeBytesMax int) ([]byte, error) {
	invariant.Require(sizeBytesMax > 0, "configuration read limit must be positive")
	invariant.Require(sizeBytesMax <= 16<<20, "configuration read limit exceeds memory budget")
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	// This descriptor is read-only; closing it cannot acknowledge buffered writes.
	defer file.Close()

	metadata, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !metadata.Mode().IsRegular() {
		return nil, errors.New("configuration must be a regular file")
	}
	if metadata.Size() > int64(sizeBytesMax) {
		return nil, errors.New("configuration file exceeds byte safety limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(sizeBytesMax)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > sizeBytesMax {
		return nil, errors.New("configuration file grew beyond byte safety limit")
	}
	return data, nil
}
