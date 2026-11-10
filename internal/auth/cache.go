package auth

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/lauritsk/sambatui/internal/privatefile"
	"github.com/oiweiwei/gokrb5.fork/v9/credentials"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
)

// CacheSnapshot freezes the selected identity and tickets. Replacing a cache
// file while a confirmation is open cannot redirect the write to a new user.
func CacheSnapshot(selector string) (Secret, string, error) {
	path, e := CachePath(selector)
	if e != nil {
		return Secret{}, "", e
	}
	f, e := privatefile.Open(path)
	if e != nil {
		return Secret{}, "", fmt.Errorf("cannot load selected Kerberos cache: %w", e)
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (16<<20)+1))
	if e != nil {
		return Secret{}, "", e
	}
	if len(b) > 16<<20 {
		return Secret{}, "", errors.New("selected Kerberos cache exceeds 16 MiB")
	}
	cache, e := decodeCache(b)
	if e != nil {
		return Secret{}, "", e
	}
	name := strings.Join(cache.DefaultPrincipal.PrincipalName.NameString, "/") + "@" + cache.DefaultPrincipal.Realm
	return NewSecret(string(b)), name, nil
}

func LoadCache(selector string, snapshot Secret) (*credentials.CCache, error) {
	if _, e := CachePath(selector); e != nil {
		return nil, e
	}
	if snapshot.Reveal() == "" {
		var e error
		snapshot, _, e = CacheSnapshot(selector)
		if e != nil {
			return nil, e
		}
	}
	return decodeCache([]byte(snapshot.Reveal()))
}

// MIT FILE cache v3/v4 encoding. Counts and lengths are checked before memory
// allocation; upstream's cache parser can allocate unbounded arrays from a bad
// file, so this small format boundary is deliberately implemented here.
type cacheReader struct {
	b   []byte
	err error
}

func (r *cacheReader) take(n int) []byte {
	if n < 0 || n > len(r.b) {
		r.err = errors.New("truncated selected Kerberos cache")
		return nil
	}
	b := r.b[:n]
	r.b = r.b[n:]
	return b
}

func (r *cacheReader) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (r *cacheReader) u32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (r *cacheReader) data() []byte         { return r.take(int(r.u32())) }
func (r *cacheReader) timestamp() time.Time { return time.Unix(int64(r.u32()), 0).UTC() }
func (r *cacheReader) count() int {
	n := int(r.u32())
	if n > len(r.b)/4 {
		r.err = errors.New("invalid selected Kerberos cache item count")
		return 0
	}
	return n
}

func (r *cacheReader) principal() credentials.Principal {
	p := credentials.Principal{}
	p.PrincipalName.NameType = int32(r.u32())
	n := r.count()
	p.Realm = string(r.data())
	for i := 0; i < n && r.err == nil; i++ {
		p.PrincipalName.NameString = append(p.PrincipalName.NameString, string(r.data()))
	}
	return p
}

func samePrincipal(a, b credentials.Principal) bool {
	return a.Realm == b.Realm && a.PrincipalName.NameType == b.PrincipalName.NameType && strings.Join(a.PrincipalName.NameString, "\x00") == strings.Join(b.PrincipalName.NameString, "\x00")
}

func decodeCache(b []byte) (*credentials.CCache, error) {
	if len(b) > 16<<20 {
		return nil, errors.New("selected Kerberos cache exceeds 16 MiB")
	}
	r := &cacheReader{b: b}
	version := r.u16()
	if version != 0x0503 && version != 0x0504 {
		return nil, errors.New("selected Kerberos cache must be MIT FILE format v3 or v4")
	}
	c := &credentials.CCache{Version: uint8(version)}
	if c.Version == 4 {
		r.take(int(r.u16()))
	}
	c.DefaultPrincipal = r.principal()
	if c.DefaultPrincipal.Realm == "" || len(c.DefaultPrincipal.PrincipalName.NameString) == 0 {
		return nil, errors.New("selected Kerberos cache has no default identity")
	}
	for len(r.b) > 0 && r.err == nil {
		start := len(r.b)
		cred := &credentials.Credential{Client: r.principal(), Server: r.principal()}
		cred.Key.KeyType = int32(r.u16())
		if c.Version == 3 {
			r.u16()
		}
		cred.Key.KeyValue = append([]byte(nil), r.data()...)
		cred.AuthTime = r.timestamp()
		cred.StartTime = r.timestamp()
		cred.EndTime = r.timestamp()
		cred.RenewTill = r.timestamp()
		sk := r.take(1)
		cred.IsSKey = len(sk) > 0 && sk[0] != 0
		cred.TicketFlags = types.NewKrbFlags()
		cred.TicketFlags.Bytes = append([]byte(nil), r.take(4)...)
		n := r.count()
		for i := 0; i < n && r.err == nil; i++ {
			cred.Addresses = append(cred.Addresses, types.HostAddress{AddrType: int32(r.u16()), Address: append([]byte(nil), r.data()...)})
		}
		n = r.count()
		for i := 0; i < n && r.err == nil; i++ {
			cred.AuthData = append(cred.AuthData, types.AuthorizationDataEntry{ADType: int32(r.u16()), ADData: append([]byte(nil), r.data()...)})
		}
		cred.Ticket = append([]byte(nil), r.data()...)
		cred.SecondTicket = append([]byte(nil), r.data()...)
		if !samePrincipal(cred.Client, c.DefaultPrincipal) {
			return nil, errors.New("selected Kerberos cache contains a different client identity")
		}
		c.Credentials = append(c.Credentials, cred)
		if len(r.b) >= start {
			return nil, errors.New("malformed selected Kerberos cache")
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	return c, nil
}
