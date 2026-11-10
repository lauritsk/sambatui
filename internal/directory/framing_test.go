package directory

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// Malicious lengths must fail on the header alone, without reading a body or
// converting an untrusted uint32 to an architecture-sized int first.
func TestLDAPHeaderBounds(t *testing.T) {
	for _, sizeBytes := range []uint32{0, 127, searchBytesMax, searchBytesMax + 1, ^uint32(0)} {
		wire := []byte{0x30, 0x84, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(wire[2:], sizeBytes)
		var header [6]byte
		count, size, err := readHeader(bytes.NewReader(wire), header[:], searchBytesMax)
		if sizeBytes <= searchBytesMax {
			if err != nil || count != 6 || uint32(size) != sizeBytes {
				t.Fatalf("size %d: count %d, size %d, error %v", sizeBytes, count, size, err)
			}
		} else if err == nil {
			t.Fatalf("accepted unbounded frame %d", sizeBytes)
		}
	}
	for _, wire := range [][]byte{{0x30, 0x80}, {0x30, 0x85}, {0x31, 0}, {0x30, 0x82, 1}} {
		var header [6]byte
		if _, _, err := readHeader(bytes.NewReader(wire), header[:], searchBytesMax); err == nil {
			t.Fatalf("accepted malformed header %x", wire)
		}
	}
}

func TestFramedConnectionPreservesFragmentedAndAdjacentMessages(t *testing.T) {
	reader, writer := net.Pipe()
	defer reader.Close()
	wire := []byte{0x30, 3, 1, 2, 3, 0x30, 0x81, 2, 4, 5}
	done := make(chan error, 1)
	go func() {
		_, err := writer.Write(wire)
		writer.Close()
		done <- err
	}()
	conn := &framedConn{Conn: reader}
	var actual bytes.Buffer
	for count := 0; count <= len(wire); count++ {
		var target [1]byte
		size, err := conn.Read(target[:])
		actual.Write(target[:size])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual.Bytes(), wire) {
		t.Fatalf("wire changed: %x", actual.Bytes())
	}
}

func TestLDAPReadBudgetIncludesOrdinaryAttributesAndOverhead(t *testing.T) {
	for _, sizeBytes := range []int{searchBytesMax - 64 - 16 - len("description"), searchBytesMax} {
		entry := ldap.NewEntry("", map[string][]string{
			"description": {strings.Repeat("x", sizeBytes)},
		})
		budget := newReadBudget()
		err := budget.entry(entry)
		if sizeBytes < searchBytesMax {
			if err != nil || budget.remainingBytes != 0 {
				t.Fatalf("exact budget: %d %v", budget.remainingBytes, err)
			}
			if err := budget.take(1); err == nil {
				t.Fatal("consumed beyond exact budget")
			}
		} else if err == nil {
			t.Fatal("ordinary attribute bypassed budget")
		}
	}
	attribute := ldap.NewEntryAttribute("member", make([]string, searchBytesMax/16))
	if err := newReadBudget().entry(&ldap.Entry{Attributes: []*ldap.EntryAttribute{attribute}}); err == nil {
		t.Fatal("empty values bypassed allocation budget")
	}
}

func TestConditionalCapabilitiesFailClosedOnMalformedResults(t *testing.T) {
	for _, result := range []*ldap.SearchResult{
		nil, {Entries: []*ldap.Entry{nil}}, {Referrals: []string{"ldap://other"}},
	} {
		session := &fakeSession{search: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return result, nil
		}, modify: func(*ldap.ModifyRequest) error {
			t.Fatal("malformed capability check dispatched a write")
			return nil
		}}
		if err := fakeClient(session).Modify(context.Background(),
			"CN=x,DC=lab,DC=invalid", "user", "1", map[string]string{"mail": "x@lab.invalid"}); err == nil {
			t.Fatal("accepted malformed capabilities")
		}
	}
}
