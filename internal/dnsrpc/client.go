package dnsrpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/lauritsk/sambatui/internal/auth"
	"github.com/lauritsk/sambatui/internal/dnsdata"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/dnsserver/v5"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
)

type Password = auth.Secret

func NewPassword(text string) Password {
	return auth.NewSecret(text)
}

type Config struct {
	Server, User                              string
	Auth, PasswordAuth, Cache, KerberosConfig string
	Password, CacheContents                   Password
	Timeout                                   time.Duration
}

func (settings Config) Format(state fmt.State, verb rune) {
	fmt.Fprintf(
		state,
		"DNSConfig{DC:%q, Auth:%q, credentials:[redacted]}",
		settings.Server,
		settings.Auth,
	)
}

type Row struct {
	Name, Type, Value        string
	TTL                      uint32
	Flags, Serial, Timestamp uint32
}

// trackedDialer owns every socket, including endpoint mapper connections. Close
// interrupts blocked IO; returning from a canceled library call alone does not.
type trackedDialer struct {
	mu       sync.Mutex
	conns    []net.Conn
	closed   bool
	attempts uint32
	timeout  time.Duration
	dial     func(context.Context, string, string) (net.Conn, error)
}

func (dialer *trackedDialer) DialContext(
	operationContext context.Context,
	network, address string,
) (net.Conn, error) {
	dialer.mu.Lock()
	if dialer.closed {
		dialer.mu.Unlock()
		return nil, net.ErrClosed
	}
	if dialer.attempts == socketsMax {
		dialer.mu.Unlock()
		return nil, errors.New("DNS RPC exceeds connection safety limit")
	}
	dialer.attempts++
	dialer.mu.Unlock()
	dial := dialer.dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: dialer.timeout}).DialContext
	}
	connection, err := dial(operationContext, network, address)
	if err != nil {
		return nil, err
	}
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	if dialer.closed {
		connection.Close()
		return nil, net.ErrClosed
	}
	dialer.conns = append(dialer.conns, connection)
	return connection, nil
}

func (dialer *trackedDialer) close() {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	if dialer.closed {
		return
	}
	dialer.closed = true
	for _, connection := range dialer.conns {
		connection.Close()
	}
	dialer.conns = nil
}

type Client struct {
	context context.Context
	conn    dcerpc.Conn
	rpc     dnsserver.DNSServerClient
	server  string
	sockets *trackedDialer
}

func (client Client) Format(state fmt.State, verb rune) {
	fmt.Fprintf(state, "DNSClient{DC:%q, credentials:[redacted]}", client.server)
}

func Dial(operationContext context.Context, settings Config) (*Client, error) {
	return dial(operationContext, settings, &trackedDialer{})
}

func dial(
	operationContext context.Context,
	settings Config,
	sockets *trackedDialer,
) (*Client, error) {
	if err := operationContext.Err(); err != nil {
		return nil, err
	}
	if settings.Server == "" {
		return nil, errors.New("DNS requires a server")
	}
	if settings.Timeout <= 0 {
		settings.Timeout = 10 * time.Second
	}
	sockets.timeout = settings.Timeout
	stop := context.AfterFunc(operationContext, sockets.close)
	defer func() {
		if operationContext.Err() != nil {
			sockets.close()
		}
		stop()
	}()
	opts, err := dialAuthentication(operationContext, settings)
	if err != nil {
		return nil, err
	}
	operationContext = gssapi.NewSecurityContext(operationContext, opts...)
	connection, err := dcerpc.Dial(
		operationContext,
		settings.Server,

		dcerpc.WithDialer(sockets),
		dcerpc.WithTimeout(settings.Timeout),

		epm.EndpointMapper(
			operationContext,
			settings.Server,
			dcerpc.WithDialer(sockets),
			dcerpc.WithTimeout(settings.Timeout),
		),
	)
	if err != nil {
		sockets.close()
		return nil, fmt.Errorf("DNS RPC connect: %w", err)
	}
	rpc, err := dnsserver.NewDNSServerClient(
		operationContext,
		connection,
		dcerpc.WithSeal(),
		dcerpc.WithEndpoint("ncacn_ip_tcp:"),
		dcerpc.WithTargetName("DNS/"+settings.Server),
	)
	if err != nil {
		sockets.close()
		connection.Close(context.Background())
		return nil, fmt.Errorf("DNS RPC authenticate: %w", err)
	}
	return &Client{
		context: operationContext,
		conn:    connection,
		rpc:     rpc,
		server:  settings.Server,
		sockets: sockets,
	}, nil
}

func (client *Client) Close() {
	client.sockets.close()
	client.conn.Close(context.Background())
}

func (client *Client) Zones(operationContext context.Context) ([]string, error) {
	stop := context.AfterFunc(operationContext, client.sockets.close)
	defer stop()
	r, err := client.rpc.ComplexOperation2(
		operationContext,
		&dnsserver.ComplexOperation2Request{
			ServerName: client.server,
			Operation:  "EnumZones",
			TypeIn:     uint32(dnsp.TypeIDDword),
			DataIn: &dnsp.Union{
				Value: &dnsp.Union_Dword{Dword: uint32(dnsp.ZoneRequestFilterPrimary)},
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("DNS enumerate zones: %w", err)
	}
	if r == nil {
		return nil, errors.New("DNS enumerate zones: missing result")
	}
	if r.Return != 0 {
		return nil, fmt.Errorf("DNS enumerate zones: status %d", r.Return)
	}
	if r.DataOut == nil {
		return nil, errors.New("DNS enumerate zones: missing result")
	}
	list, ok := r.DataOut.GetValue().(*dnsp.ZoneListW2K)
	if !ok || list == nil {
		return nil, fmt.Errorf("DNS enumerate zones: unexpected result type %d", r.TypeOut)
	}
	if len(list.ZoneArray) > zonesMax {
		return nil, errors.New("DNS enumeration exceeds 10000 zones")
	}
	zones := make([]string, 0, len(list.ZoneArray))
	for _, zone := range list.ZoneArray {
		if zone == nil || !dnsdata.ValidName(zone.ZoneName, false) {
			return nil, errors.New("DNS enumerate zones: invalid zone")
		}
		zones = append(zones, zone.ZoneName)
	}
	sort.Strings(zones)
	return zones, nil
}

const (
	socketsMax     = 32
	zonesMax       = 10000
	recordNodesMax = 10000
	recordBytesMax = 16 << 20
)
