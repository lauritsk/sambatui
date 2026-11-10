package dnsdata

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

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
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Unquoted TXT values are literal text.
func Parse(name, typ, value string) (dns.RR, error) {
	if !ValidName(name, true) {
		return nil, errors.New("bad DNS name; use @ or ASCII DNS labels (underscore allowed)")
	}
	typ = strings.ToUpper(typ)
	supported := false
	for _, t := range Types {
		if t == typ {
			supported = true
		}
	}
	if !supported {
		return nil, errors.New("supported DNS types: A, AAAA, CNAME, PTR, TXT, MX, SRV, NS")
	}
	if value == "" {
		return nil, errors.New("DNS value required")
	}
	switch typ {
	case "A", "AAAA":
		ip, e := netip.ParseAddr(value)
		if e != nil || (typ == "A" && !ip.Is4()) || (typ == "AAAA" && !ip.Is6()) {
			return nil, fmt.Errorf("invalid %s address", typ)
		}
	case "CNAME", "PTR", "NS":
		if !ValidName(value, false) {
			return nil, errors.New("target must be a DNS hostname")
		}
		if typ == "CNAME" {
			if _, e := netip.ParseAddr(strings.TrimSuffix(value, ".")); e == nil {
				return nil, errors.New("CNAME target must be a hostname, not an IP address")
			}
		}
		value = dns.Fqdn(value)
	case "MX":
		p := strings.Fields(value)
		if len(p) != 2 {
			return nil, errors.New("MX value: priority mail.example.com.")
		}
		if _, e := strconv.ParseUint(p[0], 10, 16); e != nil {
			p[0], p[1] = p[1], p[0]
		}
		if _, e := strconv.ParseUint(p[0], 10, 16); e != nil || !ValidName(p[1], false) {
			return nil, errors.New("MX needs priority 0–65535 and hostname")
		}
		value = p[0] + " " + dns.Fqdn(p[1])
	case "SRV":
		p := strings.Fields(value)
		if len(p) != 4 || !ValidName(p[3], false) {
			return nil, errors.New("SRV value: priority weight port target.example.com.")
		}
		for _, n := range p[:3] {
			if _, e := strconv.ParseUint(n, 10, 16); e != nil {
				return nil, errors.New("SRV numeric fields must be 0–65535")
			}
		}
		value = strings.Join(p[:3], " ") + " " + dns.Fqdn(p[3])
	case "TXT":
		if !strings.HasPrefix(value, `"`) {
			value = quoteTXT(value)
		}
	}
	rr, e := dns.NewRR(". 900 IN " + typ + " " + value)
	if e != nil {
		return nil, fmt.Errorf("invalid DNS record: %w", e)
	}
	if dns.Len(rr) > 65535+256 {
		return nil, errors.New("DNS record exceeds protocol size limit")
	}
	wire := make([]byte, dns.Len(rr))
	if _, e = dns.PackRR(rr, wire, 0, nil, false); e != nil {
		return nil, fmt.Errorf("invalid DNS record encoding: %w", e)
	}
	return rr, nil
}

func quoteTXT(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range []byte(s) {
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 32 || c == 127:
			fmt.Fprintf(&b, "\\%03d", c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func FQDN(name, zone string) string {
	zone = strings.TrimSuffix(zone, ".")
	if name == "@" {
		return zone
	}
	if strings.HasSuffix(name, ".") {
		return strings.TrimSuffix(name, ".")
	}
	if strings.EqualFold(name, zone) || strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(zone)) {
		return name
	}
	return name + "." + zone
}

func Reverse(ip string, zones []string) (zone, name string, ok bool) {
	a, e := netip.ParseAddr(ip)
	if e != nil || !a.Is4() {
		return "", "", false
	}
	reverse, _ := dns.ReverseAddr(ip)
	reverse = strings.TrimSuffix(reverse, ".")
	for _, z := range zones {
		z = strings.ToLower(strings.TrimSuffix(z, "."))
		if (reverse == z || strings.HasSuffix(reverse, "."+z)) && len(z) > len(zone) {
			zone = z
		}
	}
	if zone == "" {
		parts := strings.SplitN(reverse, ".", 2)
		return parts[1], parts[0], true
	}
	name = strings.TrimSuffix(reverse, "."+zone)
	if reverse == zone {
		name = "@"
	}
	return zone, name, true
}

func ReverseIP(name, zone string) string {
	full := strings.ToLower(FQDN(name, zone))
	if !strings.HasSuffix(full, ".in-addr.arpa") {
		return ""
	}
	p := strings.Split(strings.TrimSuffix(full, ".in-addr.arpa"), ".")
	if len(p) != 4 {
		return ""
	}
	ip := net.ParseIP(p[3] + "." + p[2] + "." + p[1] + "." + p[0])
	if ip == nil {
		return ""
	}
	return ip.String()
}
