package dnsrpc

import (
	"errors"

	"github.com/miekg/dns"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/record"
)

// Encode bridges DNS presentation strings to MS-DNSP octets. In particular,
// AAAA must retain 16 bytes even for mapped IPv4, and TXT escape sequences must
// be decoded once, not stored as literal backslashes by the RPC helper.
func Encode(rr dns.RR) (*record.Record, error) {
	rec, e := record.NewRecordFromRR(rr)
	if e != nil {
		return nil, e
	}
	switch v := rr.(type) {
	case *dns.AAAA:
		ip := v.AAAA.To16()
		if ip == nil {
			return nil, errors.New("invalid IPv6 record data")
		}
		rec.Buffer = append([]byte(nil), ip...)
		rec.DataLength = 16
		rec.Record = &record.Record_Record{Value: &record.Record_AAAA{RecordAAAA: &record.RecordAAAA{IPAddress: append([]byte(nil), ip...)}}}
	case *dns.TXT:
		data, e := wireData(rr)
		if e != nil {
			return nil, e
		}
		rec.Buffer = data
		rec.DataLength = uint16(len(data))
		values := []string{}
		for len(data) > 0 {
			n := int(data[0])
			data = data[1:]
			if n > len(data) {
				return nil, errors.New("invalid TXT segment")
			}
			values = append(values, string(data[:n]))
			data = data[n:]
		}
		rec.Record = &record.Record_Record{Value: &record.Record_TXT{RecordTXT: (*record.RecordTXT)(record.NewRecordString(values...))}}
	}
	return rec, nil
}

func wireData(rr dns.RR) ([]byte, error) {
	if dns.Len(rr) > 65535+256 {
		return nil, errors.New("DNS record exceeds protocol size limit")
	}
	wire := make([]byte, dns.Len(rr))
	end, e := dns.PackRR(rr, wire, 0, nil, false)
	if e != nil {
		return nil, e
	}
	_, offset, e := dns.UnpackDomainName(wire, 0)
	if e != nil {
		return nil, e
	}
	offset += 10
	if offset > end || end-offset > 65535 {
		return nil, errors.New("invalid DNS RDATA size")
	}
	return append([]byte(nil), wire[offset:end]...), nil
}
