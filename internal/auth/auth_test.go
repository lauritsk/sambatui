package auth

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oiweiwei/gokrb5.fork/v9/gssapi"
)

func TestSecretsNeverFormatOrSerialize(t *testing.T) {
	s := NewSecret("  actual secret \t")
	if s.Reveal() != "  actual secret \t" {
		t.Fatal("whitespace lost")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%f", "%x", "%#x", "%p"} {
		if strings.Contains(fmt.Sprintf(format, s), "actual secret") {
			t.Fatal("secret exposed")
		}
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "actual secret") {
		t.Fatal("secret JSON exposed")
	}
}

func TestChannelBindingRFC5929(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("synthetic DER"), SignatureAlgorithm: x509.SHA1WithRSA}
	b, e := ChannelBinding(cert)
	if e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(cert.Raw)
	expected := append([]byte("tls-server-end-point:"), hash[:]...)
	if len(b) != 20+len(expected) || binary.LittleEndian.Uint32(b[16:20]) != uint32(len(expected)) || string(b[20:]) != string(expected) {
		t.Fatal("bad channel binding")
	}
	cert.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
	if _, e = ChannelBinding(cert); e == nil {
		t.Fatal("unsupported signature accepted")
	}
}

func TestCacheSelectionExplicitOnly(t *testing.T) {
	for _, bad := range []string{"", "FILE:", "DIR:/tmp/cache", "KEYRING:persistent:1000"} {
		if _, e := CachePath(bad); e == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if p, e := CachePath("FILE:/tmp/selected"); e != nil || p != "/tmp/selected" {
		t.Fatal(p, e)
	}
}

func TestSelectedCacheSnapshotCannotChangeIdentity(t *testing.T) {
	makeCache := func(user string) []byte {
		b := &bytes.Buffer{}
		b.Write([]byte{5, 4, 0, 0})
		binary.Write(b, binary.BigEndian, uint32(1))
		binary.Write(b, binary.BigEndian, uint32(1))
		for _, s := range []string{"LAB.INVALID", user} {
			binary.Write(b, binary.BigEndian, uint32(len(s)))
			b.WriteString(s)
		}
		return b.Bytes()
	}
	path := filepath.Join(t.TempDir(), "ccache")
	os.WriteFile(path, makeCache("Reader"), 0o600)
	blob, identity, e := CacheSnapshot("FILE:" + path)
	if e != nil || identity != "Reader@LAB.INVALID" {
		t.Fatal(identity, e)
	}
	os.WriteFile(path, makeCache("Administrator"), 0o600)
	cache, e := LoadCache("FILE:"+path, blob)
	if e != nil || cache.DefaultPrincipal.PrincipalName.NameString[0] != "Reader" {
		t.Fatal("snapshot switched to replacement identity", e)
	}
	os.Remove(path)
	if _, e = LoadCache("FILE:"+path, blob); e != nil {
		t.Fatal("frozen cache disappeared with its old file", e)
	}
	if _, _, e = CacheSnapshot("FILE:" + path); e == nil {
		t.Fatal("missing explicitly selected cache did not fail")
	}
	for _, data := range []string{"", "broken", "\\x05\\x04"} {
		if _, e = LoadCache("FILE:"+path, NewSecret(data)); e == nil {
			t.Fatal("malformed cache accepted")
		}
	}
}

func TestWrapTokenRotationAndMalformedBounds(t *testing.T) {
	// 4 bytes of payload + 12 bytes of checksum, rotated right by 12.
	b := make([]byte, 32)
	copy(b, []byte{5, 4, 5, 255, 0, 12, 0, 12})
	copy(b[16:], []byte("abcdefghijkl"))
	copy(b[28:], []byte{1, 0, 0, 0})
	var tok gssapi.WrapToken
	if e := unmarshalWrap(&tok, b); e != nil {
		t.Fatal(e)
	}
	if string(tok.Payload) != string([]byte{1, 0, 0, 0}) || string(tok.CheckSum) != "abcdefghijkl" {
		t.Fatal("rotation not undone")
	}
	for _, b := range [][]byte{nil, {5, 4}, make([]byte, 16), append([]byte{5, 4, 1, 255, 255, 255}, make([]byte, 20)...)} {
		if e := unmarshalWrap(&tok, b); e == nil {
			t.Fatal("malformed token accepted")
		}
	}
}
