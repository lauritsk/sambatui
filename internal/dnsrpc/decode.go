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
func decodeNodes(b []byte) (nodes record.NodeList, err error) {
	defer func() {
		if recover() != nil {
			nodes = record.NodeList{}
			err = errors.New("malformed DNS management node buffer")
		}
	}()
	err = ndr.Unmarshal(b, &nodes, ndr.Opaque)
	return nodes, err
}

func decodeRecord(r *record.Record) (rr dns.RR, err error) {
	defer func() {
		if recover() != nil {
			rr = nil
			err = errors.New("malformed DNS management record")
		}
	}()
	if r == nil {
		return nil, errors.New("missing DNS management record")
	}
	if uint16(r.Type) == dns.TypeTXT {
		if len(r.Buffer) > 65535 {
			return nil, errors.New("invalid TXT RDATA size")
		}
		wire := make([]byte, 11+len(r.Buffer))
		binary.BigEndian.PutUint16(wire[1:3], dns.TypeTXT)
		binary.BigEndian.PutUint16(wire[3:5], dns.ClassINET)
		binary.BigEndian.PutUint32(wire[5:9], r.TTLSeconds)
		binary.BigEndian.PutUint16(wire[9:11], uint16(len(r.Buffer)))
		copy(wire[11:], r.Buffer)
		rr, _, err = dns.UnpackRR(wire, 0)
		return rr, err
	}
	rr = r.RR()
	if rr == nil {
		return nil, errors.New("unsupported DNS management record")
	}
	rr.Header().Name = "." // The node owner is carried separately by MS-DNSP.
	// Samba can return name RDATA without a root dot (notably PTR). Keep
	// presentation canonical so value-based update matching is semantic.
	switch v := rr.(type) {
	case *dns.PTR:
		v.Ptr = dns.Fqdn(v.Ptr)
	case *dns.CNAME:
		v.Target = dns.Fqdn(v.Target)
	case *dns.NS:
		v.Ns = dns.Fqdn(v.Ns)
	case *dns.MX:
		v.Mx = dns.Fqdn(v.Mx)
	case *dns.SRV:
		v.Target = dns.Fqdn(v.Target)
	}
	return rr, nil
}
