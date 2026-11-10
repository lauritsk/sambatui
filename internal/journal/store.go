package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/lifecycle"
	"github.com/lauritsk/sambatui/internal/privatefile"
	"golang.org/x/sys/unix"
)

const journalBytesMax = 16 << 20

type Record struct {
	Snapshot      lifecycle.Snapshot
	Plan          backend.Plan
	CacheIdentity string
}
type Store struct {
	path string
	lock *os.File
}

func Open(configPath string) (*Store, error) {
	path := configPath + ".pending-write.json"
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, err
	}
	descriptor, err := unix.Open(
		configPath+".lock",
		unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), configPath+".lock")
	var metadata unix.Stat_t
	if err = unix.Fstat(descriptor, &metadata); err != nil {
		file.Close()
		return nil, err
	}
	if metadata.Mode&unix.S_IFMT != unix.S_IFREG || metadata.Mode&0o077 != 0 ||
		metadata.Uid != uint32(os.Getuid()) {
		file.Close()
		return nil, errors.New("client lock must be a private regular file owned by current user")
	}
	if err = unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New(
			"another sambatui client owns this configuration; concurrent " +
				"client write flows are refused",
		)
	}
	return &Store{path, file}, nil
}

func (store *Store) Close() error {
	return store.lock.Close()
}

func (store *Store) Load() (*Record, error) {
	file, currentErr := privatefile.Open(store.path)
	if errors.Is(currentErr, os.ErrNotExist) {
		return nil, nil
	}
	if currentErr != nil {
		return nil, currentErr
	}
	defer file.Close()
	data, currentErr := io.ReadAll(io.LimitReader(file, journalBytesMax+1))
	if currentErr != nil {
		return nil, currentErr
	}
	if len(data) > journalBytesMax {
		return nil, errors.New("pending-write journal exceeds 16 MiB")
	}
	var record Record
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if currentErr = decoder.Decode(&record); currentErr != nil {
		return nil, errors.New(
			"pending-write journal is invalid; inspect original DC before " + "repairing it",
		)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("pending-write journal must contain exactly one JSON object")
	}
	if err := record.validate(); err != nil {
		return nil, err
	}
	return &record, nil
}

func (store *Store) Start(snapshot lifecycle.Snapshot, plan backend.Plan) error {
	if previous, currentErr := store.Load(); currentErr != nil {
		return currentErr
	} else if previous != nil {
		return errors.New("an unresolved pending-write journal already exists")
	}
	record := Record{Snapshot: snapshot, Plan: plan, CacheIdentity: snapshot.Settings.CacheIdentity}
	if err := record.validate(); err != nil {
		return err
	}
	record.Plan = plan.Clone()
	data, currentErr := json.MarshalIndent(record, "", "  ")
	if currentErr != nil {
		return currentErr
	}
	if len(data)+1 > journalBytesMax {
		return errors.New("pending-write journal exceeds 16 MiB")
	}
	return config.PrivateWrite(store.path, append(data, '\n'))
}

// Validate at both persistence boundaries: no intent may be written that this
// client would refuse to recover after a crash.
func (record Record) validate() error {
	if record.Snapshot.Generation == 0 || record.Snapshot.Settings.Server == "" {
		return errors.New("pending-write journal is incomplete; writes refused")
	}
	if err := record.Snapshot.Settings.Validate(false); err != nil {
		return fmt.Errorf("invalid pending-write settings; writes refused: %w", err)
	}
	if err := record.Plan.Validate(record.Snapshot.Settings); err != nil {
		return fmt.Errorf("invalid pending-write plan; writes refused: %w", err)
	}
	return nil
}

func (store *Store) Clear() error {
	if err := os.Remove(store.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir, err := os.Open(filepath.Dir(store.path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// Credentials were deliberately not persisted. After restart reconciliation
// requires an explicitly loaded matching principal on the original endpoint.
func (record Record) ReconcileSettings(current config.Settings) (config.Settings, error) {
	old := record.Snapshot.Settings
	if old.Server != current.Server || old.BaseDN != current.BaseDN || old.Auth != current.Auth ||
		old.User != current.User ||
		old.Encryption != current.Encryption ||
		old.CAFile != current.CAFile ||
		old.DNSAuth != current.DNSAuth {
		return old, errors.New(
			"reopen connection settings for the original DC, TLS and " +
				"identity before reconciling a restarted write",
		)
	}
	if old.Auth == "kerberos" && record.CacheIdentity != current.CacheIdentity {
		return old, fmt.Errorf(
			"reconciliation requires the original explicitly selected "+"cache identity %q",
			record.CacheIdentity,
		)
	}
	old.Password = current.Password
	old.CacheContents = current.CacheContents
	old.Cache = current.Cache
	old.CacheIdentity = current.CacheIdentity
	return old, old.Validate(true)
}
