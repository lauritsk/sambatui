package auth

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/lauritsk/sambatui/internal/privatefile"
	"github.com/oiweiwei/gokrb5.fork/v9/credentials"
)

const (
	cacheBytesMax       = 16 << 20
	cacheItemsMax       = 65536
	cacheCredentialsMax = 4096
)

// CacheSnapshot freezes the selected identity and tickets. Replacing a cache
// file while a confirmation is open cannot redirect the write to a new user.
func CacheSnapshot(selector string) (Secret, string, error) {
	path, err := CachePath(selector)
	if err != nil {
		return Secret{}, "", err
	}
	file, err := privatefile.Open(path)
	if err != nil {
		return Secret{}, "", fmt.Errorf("cannot load selected Kerberos cache: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, cacheBytesMax+1))
	if err != nil {
		return Secret{}, "", err
	}
	if len(data) > cacheBytesMax {
		return Secret{}, "", errors.New("selected Kerberos cache exceeds 16 MiB")
	}
	cache, err := decodeCache(data)
	if err != nil {
		return Secret{}, "", err
	}
	name := strings.Join(cache.DefaultPrincipal.PrincipalName.NameString, "/") + "@" +
		cache.DefaultPrincipal.Realm
	return NewSecret(string(data)), name, nil
}

func LoadCache(selector string, snapshot Secret) (*credentials.CCache, error) {
	if _, err := CachePath(selector); err != nil {
		return nil, err
	}
	if snapshot.Reveal() == "" {
		var err error
		snapshot, _, err = CacheSnapshot(selector)
		if err != nil {
			return nil, err
		}
	}
	return decodeCache([]byte(snapshot.Reveal()))
}

// MIT FILE cache v3/v4 encoding. Counts and lengths are checked before memory
// allocation; upstream's cache parser can allocate unbounded arrays from a bad
// file, so this small format boundary is deliberately implemented here.
type cacheReader struct {
	remaining []byte
	err       error
}

func (reader *cacheReader) take(sizeBytes int) []byte {
	if reader.err != nil {
		return nil
	}
	if sizeBytes < 0 || sizeBytes > len(reader.remaining) {
		reader.err = errors.New("truncated selected Kerberos cache")
		return nil
	}
	data := reader.remaining[:sizeBytes]
	reader.remaining = reader.remaining[sizeBytes:]
	return data
}

func (reader *cacheReader) u16() uint16 {
	data := reader.take(2)
	if data == nil {
		return 0
	}
	return binary.BigEndian.Uint16(data)
}

func (reader *cacheReader) u32() uint32 {
	data := reader.take(4)
	if data == nil {
		return 0
	}
	return binary.BigEndian.Uint32(data)
}

func (reader *cacheReader) data() []byte {
	sizeBytes := reader.u32()
	if uint64(sizeBytes) > uint64(len(reader.remaining)) {
		reader.err = errors.New("truncated selected Kerberos cache data")
		return nil
	}
	return reader.take(int(sizeBytes))
}

func (reader *cacheReader) timestamp() time.Time {
	return time.Unix(int64(reader.u32()), 0).UTC()
}

func (reader *cacheReader) count() int {
	number := reader.u32()
	if uint64(number) > uint64(len(reader.remaining)/4) || number > cacheItemsMax {
		reader.err = errors.New("invalid selected Kerberos cache item count")
		return 0
	}
	return int(number)
}

func (reader *cacheReader) principal() credentials.Principal {
	principal := credentials.Principal{}
	principal.PrincipalName.NameType = int32(reader.u32())
	componentCount := reader.count()
	principal.Realm = string(reader.data())
	principal.PrincipalName.NameString = make([]string, 0, componentCount)
	for index := 0; index < componentCount && reader.err == nil; index++ {
		principal.PrincipalName.NameString = append(
			principal.PrincipalName.NameString, string(reader.data()),
		)
	}
	return principal
}

func samePrincipal(leftPrincipal, rightPrincipal credentials.Principal) bool {
	return leftPrincipal.Realm == rightPrincipal.Realm &&
		leftPrincipal.PrincipalName.NameType == rightPrincipal.PrincipalName.NameType &&
		slices.Equal(
			leftPrincipal.PrincipalName.NameString,
			rightPrincipal.PrincipalName.NameString,
		)
}

func decodeCache(data []byte) (*credentials.CCache, error) {
	if len(data) > cacheBytesMax {
		return nil, errors.New("selected Kerberos cache exceeds 16 MiB")
	}
	reader := &cacheReader{remaining: data}
	version := reader.u16()
	if version != 0x0503 && version != 0x0504 {
		return nil, errors.New("selected Kerberos cache must be MIT FILE format v3 or v4")
	}
	cache := &credentials.CCache{Version: uint8(version)}
	if cache.Version == 4 {
		reader.take(int(reader.u16()))
	}
	cache.DefaultPrincipal = reader.principal()
	if cache.DefaultPrincipal.Realm == "" ||
		len(cache.DefaultPrincipal.PrincipalName.NameString) == 0 {
		return nil, errors.New("selected Kerberos cache has no default identity")
	}
	for count := 0; len(reader.remaining) > 0 && reader.err == nil; count++ {
		if count == cacheCredentialsMax {
			return nil, errors.New("selected Kerberos cache has too many credentials")
		}
		start := len(reader.remaining)
		currentCredential := reader.credential(cache.Version)
		if !samePrincipal(currentCredential.Client, cache.DefaultPrincipal) {
			return nil, errors.New("selected Kerberos cache contains a different client identity")
		}
		cache.Credentials = append(cache.Credentials, currentCredential)
		if len(reader.remaining) >= start {
			return nil, errors.New("malformed selected Kerberos cache")
		}
	}
	if reader.err != nil {
		return nil, reader.err
	}
	return cache, nil
}
