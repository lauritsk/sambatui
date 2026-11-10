package dnsrpc

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func directoryBlob(recordType uint16, payload []byte) []byte {
	data := make([]byte, 24+len(payload))
	binary.LittleEndian.PutUint16(data[:2], uint16(len(payload)))
	binary.LittleEndian.PutUint16(data[2:4], recordType)
	data[4], data[5] = 5, 0xf0
	binary.LittleEndian.PutUint32(data[8:12], 17)
	binary.BigEndian.PutUint32(data[12:16], 600)
	binary.LittleEndian.PutUint32(data[20:24], 99)
	copy(data[24:], payload)
	return data
}

func countedName(t *testing.T, name string) []byte {
	t.Helper()
	wire := make([]byte, 255)
	end, err := dns.PackDomainName(name, wire, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	count := byte(strings.Count(name, "."))
	if name == "." {
		count = 0
	}
	return append([]byte{byte(end), count}, wire[:end]...)
}

func TestDirectoryDNSRecordFormatsAndMetadata(t *testing.T) {
	name := countedName(t, "dc.lab.invalid.")
	numbers := make([]byte, 20)
	for index := range 5 {
		binary.BigEndian.PutUint32(numbers[index*4:], uint32(index+1))
	}
	soa := append(append(numbers, name...), countedName(t, "hostmaster.lab.invalid.")...)
	for _, test := range []struct {
		kind uint16
		data []byte
		want string
	}{
		{dns.TypeA, []byte{192, 0, 2, 1}, "192.0.2.1"},
		{dns.TypeAAAA, net.ParseIP("2001:db8::1").To16(), "2001:db8::1"},
		{dns.TypeNS, name, "dc.lab.invalid."},
		{dns.TypeCNAME, name, "dc.lab.invalid."},
		{dns.TypePTR, name, "dc.lab.invalid."},
		{dns.TypeMX, append([]byte{0, 10}, name...), "10 dc.lab.invalid."},
		{dns.TypeSRV, append([]byte{0, 1, 0, 2, 1, 133}, name...), "1 2 389 dc.lab.invalid."},
		{dns.TypeSOA, soa, "dc.lab.invalid. hostmaster.lab.invalid. 1 2 3 4 5"},
		{dns.TypeTXT, []byte{3, 'o', 'n', 'e', 3, 't', 'w', 'o'}, `"one" "two"`},
		{dns.TypeTXT, []byte{1, 0}, `"\000"`},
		{dns.TypeMX, append([]byte{0, 0}, countedName(t, ".")...), "0 ."},
	} {
		row, err := DirectoryRecord("lab.invalid", "host", directoryBlob(test.kind, test.data))
		if err != nil || row.Value != test.want || row.TTL != 600 || row.Flags != 0xf0 ||
			row.Serial != 17 || row.Timestamp != 99 || row.Name != "host" {
			t.Fatalf("type %d: row=%+v error=%v, want %q", test.kind, row, err, test.want)
		}
	}
}

func TestDirectoryDNSOwnersAreUnambiguousForSubsequentWrites(t *testing.T) {
	for _, name := range []string{"lab.invalid", "shadow.lab.invalid"} {
		row, err := DirectoryRecord("lab.invalid", name, directoryBlob(dns.TypeA, []byte{192, 0, 2, 1}))
		if err != nil {
			t.Fatal(err)
		}
		want := name + ".lab.invalid."
		if row.Name != want || qualifiedNodeName("lab.invalid", row.Name, row.Name) != want {
			t.Fatal("directory owner would address another record through RPC", row.Name)
		}
	}
}

func TestDirectoryDNSDecoderRejectsMalformedData(t *testing.T) {
	badVersion := directoryBlob(dns.TypeA, []byte{192, 0, 2, 1})
	badVersion[4] = 6
	badLength := directoryBlob(dns.TypeA, []byte{192, 0, 2, 1})
	badLength[0]++
	for _, data := range [][]byte{
		nil, make([]byte, 23), badVersion, badLength,
		directoryBlob(dns.TypeA, []byte{192, 0, 2}),
		directoryBlob(dns.TypeCNAME, []byte{2, 2, 0, 0}),
		directoryBlob(dns.TypeCNAME, []byte{3, 1, 64, 0, 0}),
		directoryBlob(dns.TypeCNAME, []byte{2, 1, 1, 'a'}),
		directoryBlob(dns.TypeSOA, make([]byte, 20)),
		directoryBlob(dns.TypeTXT, []byte{2, 'a'}),
	} {
		if _, err := DirectoryRecord("lab.invalid", "host", data); err == nil {
			t.Fatalf("malformed directory record accepted: %x", data)
		}
	}
}

func FuzzDirectoryDNSRecord(f *testing.F) {
	f.Add(directoryBlob(dns.TypeA, []byte{192, 0, 2, 1}))
	f.Add(directoryBlob(dns.TypeCNAME, []byte{1, 0, 0}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DirectoryRecord("lab.invalid", "host", data)
	})
}
