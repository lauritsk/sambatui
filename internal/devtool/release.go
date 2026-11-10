package devtool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lauritsk/sambatui/internal/invariant"
)

var releaseTargets = [...]struct{ platform, architecture string }{
	{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "amd64"}, {"darwin", "arm64"},
}

var releaseDocuments = [...]string{
	"LICENSE", "README.md", "config.example.json", "THIRD_PARTY_NOTICES.txt",
}

func (tools *Tools) Release(ctx context.Context, version, output string) (result error) {
	invariant.Require(ctx != nil, "workflow requires a context")
	invariant.Require(tools.execute != nil, "workflow requires a command runner")
	if err := validateVersion(version); err != nil {
		return err
	}
	if !filepath.IsAbs(output) {
		output = filepath.Join(tools.root, output)
	}
	if err := releaseOutputAvailable(output); err != nil {
		return err
	}
	parent := filepath.Dir(output)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	reservation, err := os.OpenFile(output+".lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("reserve release destination: %w", err)
	}
	defer func() {
		result = errors.Join(result, reservation.Close(), os.Remove(output+".lock"))
	}()

	stage, err := os.MkdirTemp(parent, ".sambatui-release-")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(stage)) }()

	if err := tools.releaseArtifacts(ctx, stage, version); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Publish only the completed fixed set. Never glob in a stale output directory.
	if err := releaseOutputAvailable(output); err != nil {
		return err
	}
	return os.Rename(filepath.Join(stage, "artifacts"), output)
}

func releaseOutputAvailable(output string) error {
	_, err := os.Lstat(output)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect release destination: %w", err)
	}
	return errors.New("release destination exists; refusing overwrite")
}

func (tools *Tools) releaseArtifacts(ctx context.Context, stage, version string) error {
	artifacts := filepath.Join(stage, "artifacts")
	if err := os.Mkdir(artifacts, 0o755); err != nil {
		return err
	}
	var manifest strings.Builder
	for _, target := range releaseTargets {
		binary := filepath.Join(stage, "sambatui")
		if _, err := tools.execute(ctx, releaseBuild(binary, version, target)); err != nil {
			return err
		}
		name := fmt.Sprintf("sambatui-%s-%s-%s.tar.gz",
			version, target.platform, target.architecture,
		)
		digest, err := tools.releaseArchive(ctx, filepath.Join(artifacts, name), binary)
		if err != nil {
			return err
		}
		fmt.Fprintf(&manifest, "%s  %s\n", digest, name)
	}
	checksums := filepath.Join(artifacts, "sambatui-"+version+"-checksums.txt")
	if err := os.WriteFile(checksums, []byte(manifest.String()), 0o644); err != nil {
		return err
	}
	return nil
}

func validateVersion(version string) error {
	if len(version) == 0 || len(version) > 64 {
		return errors.New("version must contain 1–64 ASCII characters")
	}
	for index, character := range version {
		letter := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
		digit := character >= '0' && character <= '9'
		if letter || digit {
			continue
		}
		if index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return errors.New("version must start with an ASCII letter/digit; only ._- may follow")
	}
	return nil
}

func releaseBuild(binary, version string, target struct{ platform, architecture string }) command {
	return command{
		name: "go", timeout: commandTimeout,
		arguments: []string{
			"build", "-buildvcs=false", "-trimpath", "-ldflags=-s -w -X main.version=" + version,
			"-o", binary, "./cmd/sambatui",
		},
		environment: []string{
			"CGO_ENABLED=0", "GOOS=" + target.platform, "GOARCH=" + target.architecture,
		},
	}
}
