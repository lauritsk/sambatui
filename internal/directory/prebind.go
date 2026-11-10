package directory

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/gofork/encoding/asn1"
	"github.com/lauritsk/sambatui/internal/auth"
)

// go-ldap's NTLM helper uses SICILY, not Samba's SASL GSS-SPNEGO.
func readLDAP(r io.Reader) (*ber.Packet, error) {
	var h [2]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return nil, e
	}
	if h[0] != 0x30 {
		return nil, errors.New("unexpected LDAP envelope")
	}
	header := append([]byte(nil), h[:]...)
	size := int(h[1])
	if h[1]&0x80 != 0 {
		n := int(h[1] & 0x7f)
		if n == 0 || n > 4 {
			return nil, errors.New("invalid LDAP message length")
		}
		var b [4]byte
		if _, e := io.ReadFull(r, b[4-n:]); e != nil {
			return nil, e
		}
		size = int(binary.BigEndian.Uint32(b[:]))
		header = append(header, b[4-n:]...)
	}
	if size > 1<<20 {
		return nil, errors.New("LDAP bind response exceeds 1 MiB")
	}
	b := make([]byte, len(header)+size)
	copy(b, header)
	if _, e := io.ReadFull(r, b[len(header):]); e != nil {
		return nil, e
	}
	return ber.DecodePacketErr(b)
}

func exchange(conn net.Conn, id int, op *ber.Packet, tag ber.Tag) (*ber.Packet, int64, error) {
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	envelope.AppendChild(op)
	data := envelope.Bytes()
	for len(data) > 0 {
		n, e := conn.Write(data)
		if e != nil {
			return nil, 0, e
		}
		if n == 0 {
			return nil, 0, io.ErrShortWrite
		}
		data = data[n:]
	}
	packet, e := readLDAP(conn)
	if e != nil {
		return nil, 0, e
	}
	if len(packet.Children) < 2 {
		return nil, 0, errors.New("invalid LDAP response")
	}
	msgid, ok := packet.Children[0].Value.(int64)
	if !ok || msgid != int64(id) {
		return nil, 0, errors.New("LDAP response message id mismatch")
	}
	response := packet.Children[1]
	if response.Tag != tag || len(response.Children) < 3 {
		return nil, 0, errors.New("unexpected LDAP response operation")
	}
	code, ok := response.Children[0].Value.(int64)
	if !ok {
		return nil, 0, errors.New("invalid LDAP result code")
	}
	return packet, code, nil
}

func startTLS(conn net.Conn) error {
	req := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationExtendedRequest, nil, "")
	req.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "1.3.6.1.4.1.1466.20037", ""))
	p, code, e := exchange(conn, 1, req, ldap.ApplicationExtendedResponse)
	if e != nil {
		return e
	}
	if code != 0 {
		return ldap.GetLDAPError(p)
	}
	return nil
}

func bindNTLMPayload(packet *ber.Packet) []byte {
	var payload []byte
	for _, value := range packet.Children[1].Children[3:] {
		if value.ClassType == ber.ClassContext && value.Tag == 7 {
			payload = append([]byte(nil), value.Data.Bytes()...)
		}
	}
	return payload
}

func bindNTLMRequest(token []byte) *ber.Packet {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindRequest, nil, "")
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, ""))
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	sasl := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "")
	sasl.AppendChild(ber.NewString(
		ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "GSS-SPNEGO", "",
	))
	if token != nil {
		sasl.AppendChild(ber.NewString(
			ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(token), "",
		))
	}
	request.AppendChild(sasl)
	return request
}

func bindNTLM(ctx context.Context, conn net.Conn, user string, password auth.Secret, target string, binding []byte) error {
	domain, username, ok := strings.Cut(user, `\`)
	if !ok || username == "" {
		return errors.New("NTLM requires DOMAIN\\\\user")
	}
	client := &ntlmssp.Client{Domain: domain, User: username, Password: password.Reveal(), TargetSPN: target, StripFlags: ntlmssp.FlgNegSign | ntlmssp.FlgNegSeal | ntlmssp.FlgNegKeyExch}
	client.SetChannelBindingHash(md5.Sum(binding))
	token, e := client.Negotiate()
	if e != nil {
		return e
	}
	out, e := gss.NewNegTokenInit([]asn1.ObjectIdentifier{gss.NtLmSSPMechTypeOid}, token)
	if e != nil {
		return e
	}
	for round := 0; round < 8; round++ {
		if e := ctx.Err(); e != nil {
			return e
		}
		req := bindNTLMRequest(out)
		p, code, e := exchange(conn, round+2, req, ldap.ApplicationBindResponse)
		if e != nil {
			return e
		}
		if code != 0 && code != 14 {
			return ldap.GetLDAPError(p)
		}
		payload := bindNTLMPayload(p)
		if len(payload) == 0 {
			if code == 0 && round > 0 {
				return nil
			}
			return errors.New("LDAP NTLM challenge missing")
		}
		var reply gss.NegTokenResp
		if e = reply.UnmarshalBinary(payload); e != nil {
			return e
		}
		if len(reply.SupportedMech) > 0 && !reply.SupportedMech.Equal(gss.NtLmSSPMechTypeOid) {
			return errors.New("LDAP server selected an unoffered authentication mechanism")
		}
		if code == 0 {
			if round == 0 || reply.State != gss.GssStateAcceptCompleted {
				return errors.New("invalid LDAP NTLM completion")
			}
			return nil
		}
		if round > 0 || reply.State != gss.GssStateAcceptIncomplete {
			return errors.New("unsupported LDAP NTLM negotiation state")
		}
		answer, e := client.Authenticate(reply.ResponseToken)
		if e != nil {
			return e
		}
		response, e := gss.NewNegTokenResp()
		if e != nil {
			return e
		}
		response.State = gss.GssStateAcceptIncomplete
		response.ResponseToken = answer
		out, e = response.MarshalBinary()
		if e != nil {
			return e
		}
	}
	return errors.New("LDAP NTLM exceeded handshake round limit")
}
