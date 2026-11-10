package journal

import (
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
	if e := os.MkdirAll(parent, 0o700); e != nil {
		return nil, e
	}
	fd, e := unix.Open(configPath+".lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), configPath+".lock")
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		f.Close()
		return nil, e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o077 != 0 || st.Uid != uint32(os.Getuid()) {
		f.Close()
		return nil, errors.New("client lock must be a private regular file owned by current user")
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("another sambatui client owns this configuration; concurrent client write flows are refused")
	}
	return &Store{path, f}, nil
}
func (s *Store) Close() error { return s.lock.Close() }
func (s *Store) Load() (*Record, error) {
	f, e := privatefile.Open(s.path)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, journalBytesMax+1))
	if e != nil {
		return nil, e
	}
	if len(b) > journalBytesMax {
		return nil, errors.New("pending-write journal exceeds 16 MiB")
	}
	var r Record
	if e = json.Unmarshal(b, &r); e != nil {
		return nil, errors.New("pending-write journal is invalid; inspect original DC before repairing it")
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) Start(snapshot lifecycle.Snapshot, p backend.Plan) error {
	if previous, e := s.Load(); e != nil {
		return e
	} else if previous != nil {
		return errors.New("an unresolved pending-write journal already exists")
	}
	r := Record{Snapshot: snapshot, Plan: p, CacheIdentity: snapshot.Settings.CacheIdentity}
	if err := r.validate(); err != nil {
		return err
	}
	r.Plan = p.Clone()
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return e
	}
	if len(b)+1 > journalBytesMax {
		return errors.New("pending-write journal exceeds 16 MiB")
	}
	return config.PrivateWrite(s.path, append(b, '\n'))
}

// Validate at both persistence boundaries: no intent may be written that this
// client would refuse to recover after a crash.
func (r Record) validate() error {
	if r.Snapshot.Generation == 0 || r.Snapshot.Settings.Server == "" {
		return errors.New("pending-write journal is incomplete; writes refused")
	}
	if err := r.Plan.Validate(r.Snapshot.Settings); err != nil {
		return fmt.Errorf("invalid pending-write plan; writes refused: %w", err)
	}
	return nil
}

func (s *Store) Clear() error {
	if e := os.Remove(s.path); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	dir, e := os.Open(filepath.Dir(s.path))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}

// Credentials were deliberately not persisted. After restart reconciliation
// requires an explicitly loaded matching principal on the original endpoint.
func (r Record) ReconcileSettings(current config.Settings) (config.Settings, error) {
	old := r.Snapshot.Settings
	if old.Server != current.Server || old.BaseDN != current.BaseDN || old.Auth != current.Auth || old.User != current.User || old.Encryption != current.Encryption || old.CAFile != current.CAFile || old.DNSAuth != current.DNSAuth {
		return old, errors.New("reopen connection settings for the original DC, TLS and identity before reconciling a restarted write")
	}
	if old.Auth == "kerberos" && r.CacheIdentity != current.CacheIdentity {
		return old, fmt.Errorf("reconciliation requires the original explicitly selected cache identity %q", r.CacheIdentity)
	}
	old.Password = current.Password
	old.CacheContents = current.CacheContents
	old.Cache = current.Cache
	old.CacheIdentity = current.CacheIdentity
	return old, old.Validate(true)
}
