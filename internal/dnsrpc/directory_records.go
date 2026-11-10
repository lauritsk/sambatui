package dnsrpc

import (
	"encoding/binary"
	"errors"
	"strings"

	"github.com/miekg/dns"
)

// DirectoryRecord decodes the MS-DNSP dnsRecord attribute, not an RPC record buffer.
func DirectoryRecord(zone, name string, data []byte) (Row, error) {
	if len(data) < 24 || len(data) > 24+65535 || data[4] != 5 ||
		int(binary.LittleEndian.Uint16(data[:2])) != len(data)-24 {
		return Row{}, errors.New("invalid directory DNS record header")
	}
	recordType := binary.LittleEndian.Uint16(data[2:4])
	payload, err := directoryRecordData(recordType, data[24:])
	if err != nil {
		return Row{}, err
	}
	if len(payload) > 65535 {
		return Row{}, errors.New("directory DNS record exceeds wire limit")
	}
	wire := make([]byte, 11+len(payload))
	binary.BigEndian.PutUint16(wire[1:3], recordType)
	binary.BigEndian.PutUint16(wire[3:5], dns.ClassINET)
	binary.BigEndian.PutUint32(wire[5:9], binary.BigEndian.Uint32(data[12:16]))
	binary.BigEndian.PutUint16(wire[9:11], uint16(len(payload)))
	copy(wire[11:], payload)
	resource, end, err := dns.UnpackRR(wire, 0)
	if err != nil || resource == nil || end != len(wire) {
		return Row{}, errors.New("invalid directory DNS record data")
	}
	flags := uint32(data[5])
	if name == "@" {
		flags |= 0x40000000
		if data[5] == 0xf0 {
			flags |= 0x20000000
		}
	} else if strings.EqualFold(name, zone) ||
		strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(zone)) {
		// A final root dot disambiguates these relative owners for RPC writes.
		name = dns.Fqdn(name + "." + zone)
	}
	return resourceRow(resource, name, flags, binary.LittleEndian.Uint32(data[8:12]),
		binary.LittleEndian.Uint32(data[20:24]))
}

func directoryRecordData(recordType uint16, data []byte) ([]byte, error) {
	prefix := 0
	switch recordType {
	case dns.TypeNS, dns.TypeCNAME, dns.TypePTR:
	case dns.TypeMX:
		prefix = 2
	case dns.TypeSRV:
		prefix = 6
	case dns.TypeSOA:
		return directorySOA(data)
	default:
		return data, nil
	}
	if len(data) < prefix {
		return nil, errors.New("short directory DNS record data")
	}
	name, used, err := directoryName(data[prefix:])
	if err != nil || prefix+used != len(data) {
		return nil, errors.New("invalid directory DNS target name")
	}
	result := make([]byte, 0, prefix+len(name))
	result = append(result, data[:prefix]...)
	return append(result, name...), nil
}

func directorySOA(data []byte) ([]byte, error) {
	if len(data) < 20 {
		return nil, errors.New("short directory SOA record")
	}
	primary, used, err := directoryName(data[20:])
	if err != nil {
		return nil, err
	}
	administrator, rest, err := directoryName(data[20+used:])
	if err != nil || 20+used+rest != len(data) {
		return nil, errors.New("invalid directory SOA names")
	}
	result := make([]byte, 0, len(primary)+len(administrator)+20)
	result = append(result, primary...)
	result = append(result, administrator...)
	return append(result, data[:20]...), nil
}

func directoryName(data []byte) ([]byte, int, error) {
	if len(data) < 3 || int(data[0])+2 > len(data) {
		return nil, 0, errors.New("short directory DNS name")
	}
	end, position := int(data[0])+2, 2
	for index := 0; index < int(data[1]); index++ {
		if position >= end {
			return nil, 0, errors.New("truncated directory DNS labels")
		}
		length := int(data[position])
		if length > 63 || (length == 0 && data[1] != 1) || position+length+1 >= end {
			return nil, 0, errors.New("invalid directory DNS label")
		}
		position += length + 1
	}
	if position >= end || data[position] != 0 {
		return nil, 0, errors.New("unterminated directory DNS name")
	}
	if data[1] == 1 && data[2] == 0 {
		return data[position : position+1], end, nil
	}
	return data[2 : position+1], end, nil
}
