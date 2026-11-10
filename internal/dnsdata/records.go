package dnsdata

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// Four presentation bytes can encode one RDATA byte (for example, \\255).
const valueBytesMax = 4 * 65535

var Types = []string{"A", "AAAA", "CNAME", "PTR", "TXT", "MX", "SRV", "NS"}

func ValidName(name string, root bool) bool {
	if name == "@" {
		return root
	}
	name = strings.TrimSuffix(name, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') ||
				character == '_' ||
				character == '-') {
				return false
			}
		}
	}
	return true
}

// Unquoted TXT values are literal text.
func Parse(name, recordType, value string) (dns.RR, error) {
	if len(value) > valueBytesMax {
		return nil, errors.New("DNS value exceeds presentation size limit")
	}
	if !ValidName(name, true) {
		return nil, errors.New("bad DNS name; use @ or ASCII DNS labels (underscore allowed)")
	}
	recordType = strings.ToUpper(recordType)
	supported := false
	for _, currentValue := range Types {
		if currentValue == recordType {
			supported = true
		}
	}
	if !supported {
		return nil, errors.New("supported DNS types: A, AAAA, CNAME, PTR, TXT, MX, SRV, NS")
	}
	if value == "" {
		return nil, errors.New("DNS value required")
	}
	switch recordType {
	case "A", "AAAA":
		ip, err := netip.ParseAddr(value)
		if err != nil || (recordType == "A" && !ip.Is4()) || (recordType == "AAAA" && !ip.Is6()) {
			return nil, fmt.Errorf("invalid %s address", recordType)
		}
	case "CNAME", "PTR", "NS":
		if !ValidName(value, false) {
			return nil, errors.New("target must be a DNS hostname")
		}
		if recordType == "CNAME" {
			if _, err := netip.ParseAddr(strings.TrimSuffix(value, ".")); err == nil {
				return nil, errors.New("CNAME target must be a hostname, not an IP address")
			}
		}
		value = dns.Fqdn(value)
	case "MX":
		values := strings.Fields(value)
		if len(values) != 2 {
			return nil, errors.New("MX value: priority mail.example.com.")
		}
		if _, err := strconv.ParseUint(values[0], 10, 16); err != nil {
			values[0], values[1] = values[1], values[0]
		}
		_, priorityErr := strconv.ParseUint(values[0], 10, 16)
		if priorityErr != nil || !ValidName(values[1], false) {
			return nil, errors.New("MX needs priority 0–65535 and hostname")
		}
		value = values[0] + " " + dns.Fqdn(values[1])
	case "SRV":
		values := strings.Fields(value)
		if len(values) != 4 || !ValidName(values[3], false) {
			return nil, errors.New("SRV value: priority weight port target.example.com.")
		}
		for _, valueValue := range values[:3] {
			if _, err := strconv.ParseUint(valueValue, 10, 16); err != nil {
				return nil, errors.New("SRV numeric fields must be 0–65535")
			}
		}
		value = strings.Join(values[:3], " ") + " " + dns.Fqdn(values[3])
	case "TXT":
		if !strings.HasPrefix(value, `"`) {
			value = quoteTXT(value)
		}
	}
	return parseRecord(recordType, value)
}

func parseRecord(recordType, value string) (dns.RR, error) {
	resource, err := dns.NewRR(". 900 IN " + recordType + " " + value)
	if err != nil {
		return nil, fmt.Errorf("invalid DNS record: %w", err)
	}
	if dns.Len(resource) > 65535+256 {
		return nil, errors.New("DNS record exceeds protocol size limit")
	}
	wire := make([]byte, dns.Len(resource))
	if _, err = dns.PackRR(resource, wire, 0, nil, false); err != nil {
		return nil, fmt.Errorf("invalid DNS record encoding: %w", err)
	}
	return resource, nil
}

func quoteTXT(text string) string {
	var builder strings.Builder
	builder.WriteByte('"')
	for _, character := range []byte(text) {
		switch {
		case character == '"' || character == '\\':
			builder.WriteByte('\\')
			builder.WriteByte(character)
		case character < 32 || character == 127:
			fmt.Fprintf(&builder, "\\%03d", character)
		default:
			builder.WriteByte(character)
		}
	}
	builder.WriteByte('"')
	return builder.String()
}

func FQDN(name, zone string) string {
	zone = strings.TrimSuffix(zone, ".")
	if name == "@" {
		return zone
	}
	if strings.HasSuffix(name, ".") {
		return strings.TrimSuffix(name, ".")
	}
	if strings.EqualFold(name, zone) ||
		strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(zone)) {
		return name
	}
	return name + "." + zone
}

func Reverse(ip string, zones []string) (zone, name string, ok bool) {
	address, currentErr := netip.ParseAddr(ip)
	if currentErr != nil || !address.Is4() {
		return "", "", false
	}
	reverse, err := dns.ReverseAddr(ip)
	if err != nil {
		panic("validated IPv4 address cannot be reversed: " + err.Error())
	}
	reverse = strings.TrimSuffix(reverse, ".")
	for _, value := range zones {
		value = strings.ToLower(strings.TrimSuffix(value, "."))
		if (reverse == value || strings.HasSuffix(reverse, "."+value)) && len(value) > len(zone) {
			zone = value
		}
	}
	if zone == "" {
		return "", "", false
	}
	name = strings.TrimSuffix(reverse, "."+zone)
	if reverse == zone {
		name = "@"
	}
	return zone, name, true
}
