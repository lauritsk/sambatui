package dnsrpc

import (
	"errors"

	"github.com/miekg/dns"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/record"
)

// Encode bridges DNS presentation strings to MS-DNSP octets. In particular,
// AAAA must retain 16 bytes even for mapped IPv4, and TXT escape sequences must
// be decoded once, not stored as literal backslashes by the RPC helper.
func Encode(resource dns.RR) (*record.Record, error) {
	if resource == nil {
		return nil, errors.New("missing DNS resource record")
	}
	if _, err := wireData(resource); err != nil {
		return nil, err
	}
	resourceRecord, currentErr := record.NewRecordFromRR(resource)
	if currentErr != nil {
		return nil, currentErr
	}
	switch value := resource.(type) {
	case *dns.AAAA:
		ip := value.AAAA.To16()
		if ip == nil {
			return nil, errors.New("invalid IPv6 record data")
		}
		resourceRecord.Buffer = append([]byte(nil), ip...)
		resourceRecord.DataLength = 16
		resourceRecord.Record = &record.Record_Record{
			Value: &record.Record_AAAA{
				RecordAAAA: &record.RecordAAAA{IPAddress: append([]byte(nil), ip...)},
			},
		}
	case *dns.TXT:
		data, currentErr := wireData(resource)
		if currentErr != nil {
			return nil, currentErr
		}
		resourceRecord.Buffer = data
		resourceRecord.DataLength = uint16(len(data))
		values := []string{}
		for len(data) > 0 {
			count := int(data[0])
			data = data[1:]
			if count > len(data) {
				return nil, errors.New("invalid TXT segment")
			}
			values = append(values, string(data[:count]))
			data = data[count:]
		}
		resourceRecord.Record = &record.Record_Record{
			Value: &record.Record_TXT{
				RecordTXT: (*record.RecordTXT)(record.NewRecordString(values...)),
			},
		}
	}
	return resourceRecord, nil
}

func wireData(resource dns.RR) ([]byte, error) {
	if dns.Len(resource) > 65535+256 {
		return nil, errors.New("DNS record exceeds protocol size limit")
	}
	wire := make([]byte, dns.Len(resource))
	end, err := dns.PackRR(resource, wire, 0, nil, false)
	if err != nil {
		return nil, err
	}
	_, offset, err := dns.UnpackDomainName(wire, 0)
	if err != nil {
		return nil, err
	}
	offset += 10
	if offset > end || end-offset > 65535 {
		return nil, errors.New("invalid DNS RDATA size")
	}
	return append([]byte(nil), wire[offset:end]...), nil
}
