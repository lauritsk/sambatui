package auth

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/oiweiwei/gokrb5.fork/v9/client"
	"github.com/oiweiwei/gokrb5.fork/v9/crypto"
	"github.com/oiweiwei/gokrb5.fork/v9/gssapi"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/flags"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/keyusage"
	"github.com/oiweiwei/gokrb5.fork/v9/messages"
	"github.com/oiweiwei/gokrb5.fork/v9/spnego"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
)

// CachePath resolves precisely the supplied selector. Selection of a default
// belongs to configuration loading, not authentication: no silent fallback.
func CachePath(selector string) (string, error) {
	path := strings.TrimPrefix(selector, "FILE:")
	if path == "" || strings.Contains(path, ":") {
		return "", errors.New(
			"select an explicit FILE Kerberos cache; other cache types " + "are unsupported",
		)
	}
	return path, nil
}

type boundedKDC struct {
	context context.Context
	timeout time.Duration
}

func (dialer boundedKDC) Dial(network, address string) (net.Conn, error) {
	connection, err := (&net.Dialer{Timeout: dialer.timeout}).DialContext(
		dialer.context,
		network,
		address,
	)
	if err != nil {
		return nil, err
	}
	end := time.Now().Add(dialer.timeout)
	if timestamp, ok := dialer.context.Deadline(); ok && timestamp.Before(end) {
		end = timestamp
	}
	wrapped := &boundedConn{Conn: connection, end: end}
	wrapped.stop = context.AfterFunc(dialer.context, func() {
		connection.Close()
	})
	if err = wrapped.SetDeadline(end); err != nil {
		wrapped.Close()
		return nil, err
	}
	return wrapped, nil
}

// NewKDCDialer provides cancellation and a deadline cap that protocol-library
// SetDeadline calls cannot extend. It preserves UDP's PacketConn interface.
func NewKDCDialer(operationContext context.Context, timeout time.Duration) interface {
	Dial(string, string) (net.Conn, error)
} {
	return boundedKDC{operationContext, timeout}
}

type boundedConn struct {
	net.Conn
	end  time.Time
	stop func() bool
}

func (connection *boundedConn) cap(timestamp time.Time) time.Time {
	if timestamp.IsZero() || timestamp.After(connection.end) {
		return connection.end
	}
	return timestamp
}

func (connection *boundedConn) SetDeadline(timestamp time.Time) error {
	return connection.Conn.SetDeadline(connection.cap(timestamp))
}

func (connection *boundedConn) SetReadDeadline(timestamp time.Time) error {
	return connection.Conn.SetReadDeadline(connection.cap(timestamp))
}

func (connection *boundedConn) SetWriteDeadline(timestamp time.Time) error {
	return connection.Conn.SetWriteDeadline(connection.cap(timestamp))
}

func (connection *boundedConn) Close() error {
	if connection.stop != nil {
		connection.stop()
	}
	return connection.Conn.Close()
}

func (connection *boundedConn) ReadFrom(data []byte) (int, net.Addr, error) {
	packet, ok := connection.Conn.(net.PacketConn)
	if !ok {
		return 0, nil, errors.New("KDC connection is not UDP")
	}
	return packet.ReadFrom(data)
}

func (connection *boundedConn) WriteTo(data []byte, a net.Addr) (int, error) {
	packet, ok := connection.Conn.(net.PacketConn)
	if !ok {
		return 0, errors.New("KDC connection is not UDP")
	}
	return packet.WriteTo(data, a)
}

// Kerberos implements go-ldap's GSSAPI client interface with channel binding
// and server mutual authentication. We negotiate no SASL security layer only
// because the enclosing LDAP connection is already certificate-verified TLS.
type Kerberos struct {
	context     context.Context
	client      *client.Client
	binding     []byte
	key, subkey types.EncryptionKey
	auth        types.Authenticator
	mutual      bool
}

func (Kerberos) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "Kerberos{credentials:[redacted]}")
}

func NewKerberos(
	operationContext context.Context,
	selector, configPath string,
	snapshot Secret,
	binding []byte,
	timeout time.Duration,
) (*Kerberos, error) {
	cache, err := LoadCache(selector, snapshot)
	if err != nil {
		return nil, err
	}
	settings, err := LoadKerberosConfig(configPath)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	kerberosClient, err := client.NewFromCCacheOptionalTGT(
		cache,
		settings,
		client.DisablePAFXFAST(true),
		client.Dialer(boundedKDC{operationContext, timeout}),
	)
	if err != nil {
		return nil, fmt.Errorf("selected Kerberos cache: %w", err)
	}
	return &Kerberos{
		context: operationContext,
		client:  kerberosClient,
		binding: append([]byte(nil), binding...),
	}, nil
}

func (kerberos *Kerberos) InitSecContext(target string, input []byte) ([]byte, bool, error) {
	return kerberos.InitSecContextWithOptions(target, input, nil)
}

func (kerberos *Kerberos) InitSecContextWithOptions(
	target string,
	input []byte,
	options []int,
) ([]byte, bool, error) {
	if err := kerberos.context.Err(); err != nil {
		return nil, false, err
	}
	if input == nil {
		serviceTicket, key, err := kerberos.client.GetServiceTicket(target)
		if err != nil {
			return nil, false, err
		}
		kerberos.key = key
		securityToken, err := spnego.NewKRB5TokenAPREQ(
			kerberos.client,
			serviceTicket,
			key,
			[]int{gssapi.ContextFlagMutual, gssapi.ContextFlagInteg, gssapi.ContextFlagConf},
			append(options, flags.APOptionMutualRequired),
		)
		if err != nil {
			return nil, false, err
		}
		if err = securityToken.APReq.DecryptAuthenticator(key); err != nil {
			return nil, false, err
		}
		kerberos.auth = securityToken.APReq.Authenticator
		if len(kerberos.auth.Cksum.Checksum) < 24 {
			return nil, false, errors.New("invalid Kerberos GSS checksum")
		}
		copy(kerberos.auth.Cksum.Checksum[4:20], bindingHash(kerberos.binding))
		ap, err := messages.NewAPReq(serviceTicket, key, kerberos.auth)
		if err != nil {
			return nil, false, err
		}
		ap.APOptions = securityToken.APReq.APOptions
		securityToken.APReq = ap
		data, err := securityToken.Marshal()
		return data, true, err
	}
	var securityToken spnego.KRB5Token
	if err := securityToken.Unmarshal(input); err != nil {
		return nil, false, err
	}
	if securityToken.IsKRBError() {
		return nil, false, securityToken.KRBError
	}
	if !securityToken.IsAPRep() {
		return nil, false, errors.New("Kerberos server did not supply mutual authentication")
	}
	plain, err := crypto.DecryptEncPart(
		securityToken.APRep.EncPart,
		kerberos.key,
		keyusage.AP_REP_ENCPART,
	)
	if err != nil {
		return nil, false, err
	}
	var reply messages.EncAPRepPart
	if err = reply.Unmarshal(plain); err != nil {
		return nil, false, err
	}
	if !reply.CTime.Equal(kerberos.auth.CTime) || reply.Cusec != kerberos.auth.Cusec {
		return nil, false, errors.New("Kerberos mutual authentication timestamp mismatch")
	}
	kerberos.subkey = reply.Subkey
	kerberos.mutual = true
	return []byte{}, false, nil
}

func (kerberos *Kerberos) NegotiateSaslAuth(input []byte, authzid string) ([]byte, error) {
	if !kerberos.mutual {
		return nil, errors.New("Kerberos server not authenticated")
	}
	var securityToken gssapi.WrapToken
	if err := unmarshalWrap(&securityToken, input); err != nil {
		return nil, err
	}
	if securityToken.Flags&1 == 0 {
		return nil, errors.New("Kerberos SASL token is not from server")
	}
	key := kerberos.key
	if securityToken.Flags&4 != 0 {
		key = kerberos.subkey
	}
	if _, err := securityToken.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		return nil, errors.New("Kerberos SASL signature verification failed")
	}
	if len(securityToken.Payload) != 4 || securityToken.Payload[0]&1 == 0 {
		return nil, errors.New("Kerberos server does not allow TLS-only SASL layer")
	}
	encryptionType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	out := gssapi.WrapToken{
		Flags:     securityToken.Flags & 4,
		EC:        uint16(encryptionType.GetHMACBitLength() / 8),
		SndSeqNum: 1,
		Payload:   append([]byte{1, 0, 0, 0}, []byte(authzid)...),
	}
	if err = out.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}
	return out.Marshal()
}

// RFC 4121 permits rotating the token body; gokrb5's decoder does not
// unrotate it. Normalize without touching the authenticated header fields.
func unmarshalWrap(securityToken *gssapi.WrapToken, input []byte) error {
	if len(input) <= 16 {
		return errors.New("Kerberos SASL token too short")
	}
	data := append([]byte(nil), input...)
	body := data[16:]
	number := int(binary.BigEndian.Uint16(data[6:8])) % len(body)
	rotated := append(append([]byte(nil), body[number:]...), body[:number]...)
	copy(body, rotated)
	binary.BigEndian.PutUint16(data[6:8], 0)
	if err := securityToken.Unmarshal(data, true); err != nil {
		return err
	}
	if securityToken.Flags&2 != 0 {
		return errors.New("sealed Kerberos SASL negotiation token unsupported")
	}
	return nil
}

func (kerberos *Kerberos) DeleteSecContext() error {
	kerberos.key = types.EncryptionKey{}
	kerberos.subkey = types.EncryptionKey{}
	kerberos.client.Destroy()
	return nil
}
