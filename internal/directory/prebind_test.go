package directory

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/lauritsk/sambatui/internal/auth"
)

func reply(c net.Conn, id int64, tag ber.Tag, code int, token []byte) error {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	if token != nil {
		op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, string(token), ""))
	}
	p.AppendChild(op)
	_, e := c.Write(p.Bytes())
	return e
}

func TestNTLMSASLTransmitsActualChannelBindingWithMICAndNTLMv2(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	server.SetDeadline(time.Now().Add(2 * time.Second))
	binding := []byte("synthetic RFC 2744 TLS binding")
	done := make(chan error, 1)
	go func() {
		done <- func() error {
			first, e := readLDAP(server)
			if e != nil {
				return e
			}
			sasl := first.Children[1].Children[2]
			if sasl.Children[0].Value != "GSS-SPNEGO" {
				return fmt.Errorf("not SASL SPNEGO")
			}
			var init gss.NegTokenInit
			if e = init.UnmarshalBinary(sasl.Children[1].Data.Bytes()); e != nil {
				return e
			}
			acceptor := &ntlmssp.Server{TargetName: "LAB", NetBIOSDomain: "LAB", NetBIOSName: "DC", DnsDomainName: "lab.invalid", DnsComputerName: "dc.lab.invalid"}
			challenge, e := acceptor.AcceptNegotiate(init.Data.MechToken)
			if e != nil {
				return e
			}
			if acceptor.Negotiate.NegotiateFlags&(ntlmssp.FlgNegSign|ntlmssp.FlgNegSeal) != 0 {
				return fmt.Errorf("SASL signing/sealing requested inside verified TLS")
			}
			if acceptor.Negotiate.NegotiateFlags&ntlmssp.FlgNegExtendedSessionSecurity == 0 {
				return fmt.Errorf("NTLMv2 extended session security omitted")
			}
			resp, _ := gss.NewNegTokenResp()
			resp.State = gss.GssStateAcceptIncomplete
			resp.SupportedMech = gss.NtLmSSPMechTypeOid
			resp.ResponseToken = challenge
			token, e := resp.MarshalBinary()
			if e != nil {
				return e
			}
			if e = reply(server, 2, ldap.ApplicationBindResponse, 14, token); e != nil {
				return e
			}
			second, e := readLDAP(server)
			if e != nil {
				return e
			}
			if e = resp.UnmarshalBinary(second.Children[1].Children[2].Children[1].Data.Bytes()); e != nil {
				return e
			}
			am, e := acceptor.AcceptAuthenticate(resp.ResponseToken)
			if e != nil {
				return e
			}
			if len(am.MIC) != 16 || bytes.Equal(am.MIC, make([]byte, 16)) {
				return fmt.Errorf("NTLM message integrity code missing")
			}
			if len(am.NtChallengeResponse) < 48 || am.NtChallengeResponse[16] != 1 {
				return fmt.Errorf("not an NTLMv2 response")
			}
			expected := md5.Sum(binding)
			av := am.NtChallengeResponse[44:]
			found := false
			for len(av) >= 4 {
				typ, n := binary.LittleEndian.Uint16(av[:2]), int(binary.LittleEndian.Uint16(av[2:4]))
				av = av[4:]
				if len(av) < n {
					return fmt.Errorf("bad NTLM AV length")
				}
				if typ == ntlmssp.MsvAvChannelBindings {
					found = bytes.Equal(av[:n], expected[:])
				}
				av = av[n:]
				if typ == 0 {
					break
				}
			}
			if !found {
				return fmt.Errorf("real TLS channel binding absent from NTLM response")
			}
			resp, _ = gss.NewNegTokenResp()
			resp.State = gss.GssStateAcceptCompleted
			token, e = resp.MarshalBinary()
			if e != nil {
				return e
			}
			return reply(server, 3, ldap.ApplicationBindResponse, 0, token)
		}()
	}()
	e := bindNTLM(context.Background(), client, `LAB\Alice`, auth.NewSecret("  whitespace password  "), "ldap/dc.lab.invalid", binding)
	if e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestLDAPFramingRejectsMalformedAndOversizeInput(t *testing.T) {
	for _, b := range [][]byte{{0x31, 0}, {0x30, 0x80}, {0x30, 0x85}, {0x30, 0x84, 0x10, 0, 0, 0}, {0x30, 0x82, 1}, {0x30, 3, 1}} {
		if _, e := readLDAP(bytes.NewReader(b)); e == nil {
			t.Fatalf("accepted malformed input %x", b)
		}
	}
}
