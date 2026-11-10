package directory

import (
	"context"
	"errors"
	"io"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/jfjallid/go-smb/gss"
	"github.com/lauritsk/sambatui/internal/auth"
)

// go-ldap's NTLM helper uses SICILY, not Samba's SASL GSS-SPNEGO.
func readLDAP(reader io.Reader) (*ber.Packet, error) {
	var header [6]byte
	count, sizeBytes, err := readHeader(reader, header[:], 1<<20)
	if err != nil {
		return nil, err
	}
	data := make([]byte, count+sizeBytes)
	copy(data, header[:count])
	if _, currentErr := io.ReadFull(reader, data[count:]); currentErr != nil {
		return nil, currentErr
	}
	return ber.DecodePacketErr(data)
}

func exchange(conn net.Conn, id int, op *ber.Packet, tag ber.Tag) (*ber.Packet, int64, error) {
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	envelope.AppendChild(
		ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""),
	)
	envelope.AppendChild(op)
	data := envelope.Bytes()
	for len(data) > 0 {
		count, err := conn.Write(data)
		if err != nil {
			return nil, 0, err
		}
		if count == 0 {
			return nil, 0, io.ErrShortWrite
		}
		data = data[count:]
	}
	packet, err := readLDAP(conn)
	if err != nil {
		return nil, 0, err
	}
	if len(packet.Children) < 2 {
		return nil, 0, errors.New("invalid LDAP response")
	}
	messageID, ok := packet.Children[0].Value.(int64)
	if !ok || messageID != int64(id) {
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
	request := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldap.ApplicationExtendedRequest,
		nil,
		"",
	)
	request.AppendChild(
		ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "1.3.6.1.4.1.1466.20037", ""),
	)
	packet, code, err := exchange(conn, 1, request, ldap.ApplicationExtendedResponse)
	if err != nil {
		return err
	}
	if code != 0 {
		return ldap.GetLDAPError(packet)
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
	request := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldap.ApplicationBindRequest,
		nil,
		"",
	)
	request.AppendChild(
		ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, ""),
	)
	request.AppendChild(
		ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""),
	)
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

func bindNTLM(
	operationContext context.Context,
	conn net.Conn,
	user string,
	password auth.Secret,
	target string,
	binding []byte,
) error {
	client, out, err := bindNTLMClient(user, password, target, binding)
	if err != nil {
		return err
	}
	for round := 0; round < 8; round++ {
		if err := operationContext.Err(); err != nil {
			return err
		}
		request := bindNTLMRequest(out)
		packet, code, err := exchange(conn, round+2, request, ldap.ApplicationBindResponse)
		if err != nil {
			return err
		}
		if code != 0 && code != 14 {
			return ldap.GetLDAPError(packet)
		}
		payload := bindNTLMPayload(packet)
		if len(payload) == 0 {
			if code == 0 && round > 0 {
				return nil
			}
			return errors.New("LDAP NTLM challenge missing")
		}
		var reply gss.NegTokenResp
		if err = reply.UnmarshalBinary(payload); err != nil {
			return err
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
		answer, err := client.Authenticate(reply.ResponseToken)
		if err != nil {
			return err
		}
		response, err := gss.NewNegTokenResp()
		if err != nil {
			return err
		}
		response.State = gss.GssStateAcceptIncomplete
		response.ResponseToken = answer
		out, err = response.MarshalBinary()
		if err != nil {
			return err
		}
	}
	return errors.New("LDAP NTLM exceeded handshake round limit")
}
