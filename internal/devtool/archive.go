package devtool

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/lauritsk/sambatui/internal/invariant"
)

const releaseFileBytesMax = 128 << 20

func (tools *Tools) releaseArchive(
	ctx context.Context, path, binary string,
) (digest string, result error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	compressed, err := gzip.NewWriterLevel(io.MultiWriter(file, hash), gzip.BestCompression)
	if err != nil {
		return "", errors.Join(err, file.Close())
	}
	compressed.Header = gzip.Header{ModTime: time.Unix(0, 0).UTC(), OS: 255}
	archive := tar.NewWriter(compressed)
	defer func() {
		result = errors.Join(result, archive.Close(), compressed.Close(), file.Close())
		if result == nil {
			digest = hex.EncodeToString(hash.Sum(nil))
		}
	}()

	if err := archiveFile(ctx, archive, binary, "sambatui", 0o755); err != nil {
		return "", err
	}
	for _, name := range releaseDocuments {
		source := filepath.Join(tools.root, name)
		if err := archiveFile(ctx, archive, source, name, 0o644); err != nil {
			return "", err
		}
	}
	return "", nil
}

func archiveFile(
	ctx context.Context, archive *tar.Writer, path, name string, mode int64,
) (result error) {
	metadata, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !metadata.Mode().IsRegular() || metadata.Size() > releaseFileBytesMax {
		return errors.New("release input must be a regular non-symlink file of at most 128 MiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(metadata, opened) {
		return errors.New("release input changed during open")
	}

	// Stable metadata makes archives reproducible across users, hosts and runs.
	if err := archive.WriteHeader(&tar.Header{
		Name: name, Mode: mode, Size: metadata.Size(), Typeflag: tar.TypeReg,
		ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR,
	}); err != nil {
		return err
	}
	_, err = io.CopyN(archive, contextReader{ctx, file}, metadata.Size())
	return err
}

type contextReader struct {
	context context.Context
	source  io.Reader
}

func (reader contextReader) Read(target []byte) (int, error) {
	invariant.Require(reader.context != nil, "archive reader requires a context")
	invariant.Require(reader.source != nil, "archive reader requires a source")
	if err := reader.context.Err(); err != nil {
		return 0, err
	}
	return reader.source.Read(target)
}
