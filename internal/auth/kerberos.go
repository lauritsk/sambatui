package auth

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/oiweiwei/gokrb5.fork/v9/client"
	"github.com/oiweiwei/gokrb5.fork/v9/config"
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
		return "", errors.New("select an explicit FILE Kerberos cache; other cache types are unsupported")
	}
	return path, nil
}

type boundedKDC struct {
	ctx     context.Context
	timeout time.Duration
}

func (d boundedKDC) Dial(network, address string) (net.Conn, error) {
	c, e := (&net.Dialer{Timeout: d.timeout}).DialContext(d.ctx, network, address)
	if e != nil {
		return nil, e
	}
	end := time.Now().Add(d.timeout)
	if t, ok := d.ctx.Deadline(); ok && t.Before(end) {
		end = t
	}
	wrapped := &boundedConn{Conn: c, end: end}
	wrapped.stop = context.AfterFunc(d.ctx, func() { c.Close() })
	if e = wrapped.SetDeadline(end); e != nil {
		wrapped.Close()
		return nil, e
	}
	return wrapped, nil
}

// NewKDCDialer provides cancellation and a deadline cap that protocol-library
// SetDeadline calls cannot extend. It preserves UDP's PacketConn interface.
func NewKDCDialer(ctx context.Context, timeout time.Duration) interface {
	Dial(string, string) (net.Conn, error)
} {
	return boundedKDC{ctx, timeout}
}

type boundedConn struct {
	net.Conn
	end  time.Time
	stop func() bool
}

func (c *boundedConn) cap(t time.Time) time.Time {
	if t.IsZero() || t.After(c.end) {
		return c.end
	}
	return t
}
func (c *boundedConn) SetDeadline(t time.Time) error     { return c.Conn.SetDeadline(c.cap(t)) }
func (c *boundedConn) SetReadDeadline(t time.Time) error { return c.Conn.SetReadDeadline(c.cap(t)) }

func (c *boundedConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(c.cap(t)) }

func (c *boundedConn) Close() error {
	if c.stop != nil {
		c.stop()
	}
	return c.Conn.Close()
}

func (c *boundedConn) ReadFrom(b []byte) (int, net.Addr, error) {
	p, ok := c.Conn.(net.PacketConn)
	if !ok {
		return 0, nil, errors.New("KDC connection is not UDP")
	}
	return p.ReadFrom(b)
}

func (c *boundedConn) WriteTo(b []byte, a net.Addr) (int, error) {
	p, ok := c.Conn.(net.PacketConn)
	if !ok {
		return 0, errors.New("KDC connection is not UDP")
	}
	return p.WriteTo(b, a)
}

// Kerberos implements go-ldap's GSSAPI client interface with channel binding
// and server mutual authentication. We negotiate no SASL security layer only
// because the enclosing LDAP connection is already certificate-verified TLS.
type Kerberos struct {
	ctx         context.Context
	client      *client.Client
	binding     []byte
	key, subkey types.EncryptionKey
	auth        types.Authenticator
	mutual      bool
}

func (Kerberos) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "Kerberos{credentials:[redacted]}")
}

func NewKerberos(ctx context.Context, selector, configPath string, snapshot Secret, binding []byte, timeout time.Duration) (*Kerberos, error) {
	cc, e := LoadCache(selector, snapshot)
	if e != nil {
		return nil, e
	}
	if configPath == "" {
		configPath = os.Getenv("KRB5_CONFIG")
	}
	if configPath == "" {
		configPath = "/etc/krb5.conf"
	}
	cfg, e := config.Load(configPath)
	if e != nil {
		return nil, fmt.Errorf("Kerberos configuration: %w", e)
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	cl, e := client.NewFromCCacheOptionalTGT(cc, cfg, client.DisablePAFXFAST(true), client.Dialer(boundedKDC{ctx, timeout}))
	if e != nil {
		return nil, fmt.Errorf("selected Kerberos cache: %w", e)
	}
	return &Kerberos{ctx: ctx, client: cl, binding: append([]byte(nil), binding...)}, nil
}

func (k *Kerberos) InitSecContext(target string, input []byte) ([]byte, bool, error) {
	return k.InitSecContextWithOptions(target, input, nil)
}

func (k *Kerberos) InitSecContextWithOptions(target string, input []byte, options []int) ([]byte, bool, error) {
	if e := k.ctx.Err(); e != nil {
		return nil, false, e
	}
	if input == nil {
		tkt, key, e := k.client.GetServiceTicket(target)
		if e != nil {
			return nil, false, e
		}
		k.key = key
		tok, e := spnego.NewKRB5TokenAPREQ(k.client, tkt, key, []int{gssapi.ContextFlagMutual, gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, append(options, flags.APOptionMutualRequired))
		if e != nil {
			return nil, false, e
		}
		if e = tok.APReq.DecryptAuthenticator(key); e != nil {
			return nil, false, e
		}
		k.auth = tok.APReq.Authenticator
		if len(k.auth.Cksum.Checksum) < 24 {
			return nil, false, errors.New("invalid Kerberos GSS checksum")
		}
		copy(k.auth.Cksum.Checksum[4:20], bindingHash(k.binding))
		ap, e := messages.NewAPReq(tkt, key, k.auth)
		if e != nil {
			return nil, false, e
		}
		ap.APOptions = tok.APReq.APOptions
		tok.APReq = ap
		b, e := tok.Marshal()
		return b, true, e
	}
	var tok spnego.KRB5Token
	if e := tok.Unmarshal(input); e != nil {
		return nil, false, e
	}
	if tok.IsKRBError() {
		return nil, false, tok.KRBError
	}
	if !tok.IsAPRep() {
		return nil, false, errors.New("Kerberos server did not supply mutual authentication")
	}
	plain, e := crypto.DecryptEncPart(tok.APRep.EncPart, k.key, keyusage.AP_REP_ENCPART)
	if e != nil {
		return nil, false, e
	}
	var rep messages.EncAPRepPart
	if e = rep.Unmarshal(plain); e != nil {
		return nil, false, e
	}
	if !rep.CTime.Equal(k.auth.CTime) || rep.Cusec != k.auth.Cusec {
		return nil, false, errors.New("Kerberos mutual authentication timestamp mismatch")
	}
	k.subkey = rep.Subkey
	k.mutual = true
	return []byte{}, false, nil
}

func (k *Kerberos) NegotiateSaslAuth(input []byte, authzid string) ([]byte, error) {
	if !k.mutual {
		return nil, errors.New("Kerberos server not authenticated")
	}
	var tok gssapi.WrapToken
	if e := unmarshalWrap(&tok, input); e != nil {
		return nil, e
	}
	if tok.Flags&1 == 0 {
		return nil, errors.New("Kerberos SASL token is not from server")
	}
	key := k.key
	if tok.Flags&4 != 0 {
		key = k.subkey
	}
	if _, e := tok.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL); e != nil {
		return nil, errors.New("Kerberos SASL signature verification failed")
	}
	if len(tok.Payload) != 4 || tok.Payload[0]&1 == 0 {
		return nil, errors.New("Kerberos server does not allow TLS-only SASL layer")
	}
	et, e := crypto.GetEtype(key.KeyType)
	if e != nil {
		return nil, e
	}
	out := gssapi.WrapToken{Flags: tok.Flags & 4, EC: uint16(et.GetHMACBitLength() / 8), SndSeqNum: 1, Payload: append([]byte{1, 0, 0, 0}, []byte(authzid)...)}
	if e = out.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); e != nil {
		return nil, e
	}
	return out.Marshal()
}

// RFC 4121 permits rotating the token body; gokrb5's decoder does not
// unrotate it. Normalize without touching the authenticated header fields.
func unmarshalWrap(tok *gssapi.WrapToken, input []byte) error {
	if len(input) <= 16 {
		return errors.New("Kerberos SASL token too short")
	}
	b := append([]byte(nil), input...)
	body := b[16:]
	r := int(binary.BigEndian.Uint16(b[6:8])) % len(body)
	rotated := append(append([]byte(nil), body[r:]...), body[:r]...)
	copy(body, rotated)
	binary.BigEndian.PutUint16(b[6:8], 0)
	if e := tok.Unmarshal(b, true); e != nil {
		return e
	}
	if tok.Flags&2 != 0 {
		return errors.New("sealed Kerberos SASL negotiation token unsupported")
	}
	return nil
}

func (k *Kerberos) DeleteSecContext() error {
	k.key = types.EncryptionKey{}
	k.subkey = types.EncryptionKey{}
	k.client.Destroy()
	return nil
}
