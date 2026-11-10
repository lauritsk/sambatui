package dnsrpc

import (
	"encoding/binary"
	"errors"

	"github.com/miekg/dns"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/record"
	"github.com/oiweiwei/go-msrpc/ndr"
)

// These boundaries contain malformed untrusted wire data, not application or
// UI errors. No decoder panic is allowed to become partial-success output.
func decodeNodes(data []byte) (nodes record.NodeList, err error) {
	defer func() {
		if recover() != nil {
			nodes = record.NodeList{}
			err = errors.New("malformed DNS management node buffer")
		}
	}()
	if len(data) > recordBytesMax {
		return record.NodeList{}, errors.New("DNS management node buffer exceeds safety limit")
	}
	err = ndr.Unmarshal(data, &nodes, ndr.Opaque)
	return nodes, err
}

func decodeRecord(currentRecord *record.Record) (resource dns.RR, err error) {
	defer func() {
		if recover() != nil {
			resource = nil
			err = errors.New("malformed DNS management record")
		}
	}()
	if currentRecord == nil {
		return nil, errors.New("missing DNS management record")
	}
	if uint16(currentRecord.Type) == dns.TypeTXT {
		if len(currentRecord.Buffer) > 65535 {
			return nil, errors.New("invalid TXT RDATA size")
		}
		wire := make([]byte, 11+len(currentRecord.Buffer))
		binary.BigEndian.PutUint16(wire[1:3], dns.TypeTXT)
		binary.BigEndian.PutUint16(wire[3:5], dns.ClassINET)
		binary.BigEndian.PutUint32(wire[5:9], currentRecord.TTLSeconds)
		binary.BigEndian.PutUint16(wire[9:11], uint16(len(currentRecord.Buffer)))
		copy(wire[11:], currentRecord.Buffer)
		resource, _, err = dns.UnpackRR(wire, 0)
		return resource, err
	}
	resource = currentRecord.RR()
	if resource == nil {
		return nil, errors.New("unsupported DNS management record")
	}
	resource.Header().Name = "." // The node owner is carried separately by MS-DNSP.
	// Samba can return name RDATA without a root dot (notably PTR). Keep
	// presentation canonical so value-based update matching is semantic.
	switch value := resource.(type) {
	case *dns.PTR:
		value.Ptr = dns.Fqdn(value.Ptr)
	case *dns.CNAME:
		value.Target = dns.Fqdn(value.Target)
	case *dns.NS:
		value.Ns = dns.Fqdn(value.Ns)
	case *dns.MX:
		value.Mx = dns.Fqdn(value.Mx)
	case *dns.SRV:
		value.Target = dns.Fqdn(value.Target)
	}
	return resource, nil
}
