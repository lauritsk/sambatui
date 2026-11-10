package dnsrpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lauritsk/sambatui/internal/auth"
	"github.com/miekg/dns"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/dnsserver/v5"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/record"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
	"github.com/oiweiwei/go-msrpc/ndr"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/oiweiwei/go-msrpc/ssp/krb5"
	kconfig "github.com/oiweiwei/gokrb5.fork/v9/config"
)

type Password = auth.Secret

func NewPassword(s string) Password { return auth.NewSecret(s) }

type Config struct {
	Server, User                              string
	Auth, PasswordAuth, Cache, KerberosConfig string
	Password, CacheContents                   Password
	Timeout                                   time.Duration
}

func (c Config) Format(state fmt.State, verb rune) {
	fmt.Fprintf(state, "DNSConfig{DC:%q, Auth:%q, credentials:[redacted]}", c.Server, c.Auth)
}

type Row struct {
	Name, Type, Value        string
	TTL                      uint32
	Flags, Serial, Timestamp uint32
}

// trackedDialer owns every socket, including endpoint mapper connections. Close
// interrupts blocked IO; returning from a canceled library call alone does not.
type trackedDialer struct {
	mu      sync.Mutex
	conns   []net.Conn
	closed  bool
	timeout time.Duration
	dial    func(context.Context, string, string) (net.Conn, error)
}

func (d *trackedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dial := d.dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: d.timeout}).DialContext
	}
	c, e := dial(ctx, network, address)
	if e != nil {
		return nil, e
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		c.Close()
		return nil, net.ErrClosed
	}
	d.conns = append(d.conns, c)
	return c, nil
}

func (d *trackedDialer) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	for _, c := range d.conns {
		c.Close()
	}
}

type Client struct {
	ctx     context.Context
	conn    dcerpc.Conn
	rpc     dnsserver.DNSServerClient
	server  string
	sockets *trackedDialer
}

func (c Client) Format(state fmt.State, verb rune) {
	fmt.Fprintf(state, "DNSClient{DC:%q, credentials:[redacted]}", c.server)
}

func Dial(ctx context.Context, cfg Config) (*Client, error) { return dial(ctx, cfg, &trackedDialer{}) }

func dial(ctx context.Context, cfg Config, sockets *trackedDialer) (*Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cfg.Server == "" {
		return nil, errors.New("DNS requires a server")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	sockets.timeout = cfg.Timeout
	stop := context.AfterFunc(ctx, sockets.close)
	defer func() {
		if ctx.Err() != nil {
			sockets.close()
		}
		stop()
	}()
	var opts []gssapi.ContextOption
	switch cfg.Auth {
	case "", "password":
		if cfg.User == "" || cfg.Password.Reveal() == "" {
			return nil, errors.New("DNS requires username and password")
		}
		mechanism := gssapi.WithMechanismFactory(ssp.NTLM)
		if cfg.PasswordAuth == "kerberos" {
			krbCfg, e := kerberosSettings(ctx, cfg)
			if e != nil {
				return nil, e
			}
			cred, e := serviceCredential(ctx, cfg, krbCfg)
			if e != nil {
				return nil, e
			}
			opts = []gssapi.ContextOption{gssapi.WithCredential(cred), gssapi.WithMechanismFactory(ssp.KRB5, krbCfg)}
			mechanism = nil
		} else if cfg.PasswordAuth != "" && cfg.PasswordAuth != "ntlm" {
			return nil, errors.New("DNS password auth must be ntlm or kerberos")
		}
		if mechanism != nil {
			opts = []gssapi.ContextOption{gssapi.WithCredential(credential.NewFromPassword(cfg.User, cfg.Password.Reveal())), mechanism}
		}
	case "kerberos":
		// Load first so a missing explicit selector fails before any network IO.
		if _, e := auth.LoadCache(cfg.Cache, cfg.CacheContents); e != nil {
			return nil, e
		}
		krbCfg, e := kerberosSettings(ctx, cfg)
		if e != nil {
			return nil, e
		}
		cred, e := serviceCredential(ctx, cfg, krbCfg)
		if e != nil {
			return nil, e
		}
		opts = []gssapi.ContextOption{gssapi.WithCredential(cred), gssapi.WithMechanismFactory(ssp.KRB5, krbCfg)}
	default:
		return nil, errors.New("DNS auth must be password or kerberos")
	}
	// The upstream provider also recognizes a nonstandard ambient variable.
	// Reject it rather than allowing it to seed a different principal's TGT.
	if (cfg.Auth == "kerberos" || cfg.PasswordAuth == "kerberos") && os.Getenv("KRB5_CCACHE") != "" {
		return nil, errors.New("unset nonstandard KRB5_CCACHE; select the cache explicitly with SAMBATUI_KRB5_CCACHE")
	}
	ctx = gssapi.NewSecurityContext(ctx, opts...)
	cc, err := dcerpc.Dial(ctx, cfg.Server,
		dcerpc.WithDialer(sockets), dcerpc.WithTimeout(cfg.Timeout),
		epm.EndpointMapper(ctx, cfg.Server, dcerpc.WithDialer(sockets), dcerpc.WithTimeout(cfg.Timeout)))
	if err != nil {
		sockets.close()
		return nil, fmt.Errorf("DNS RPC connect: %w", err)
	}
	rpc, err := dnsserver.NewDNSServerClient(ctx, cc, dcerpc.WithSeal(), dcerpc.WithEndpoint("ncacn_ip_tcp:"), dcerpc.WithTargetName("DNS/"+cfg.Server))
	if err != nil {
		sockets.close()
		cc.Close(context.Background())
		return nil, fmt.Errorf("DNS RPC authenticate: %w", err)
	}
	return &Client{ctx: ctx, conn: cc, rpc: rpc, server: cfg.Server, sockets: sockets}, nil
}

func kerberosSettings(ctx context.Context, cfg Config) (*krb5.Config, error) {
	path := cfg.KerberosConfig
	if path == "" {
		path = os.Getenv("KRB5_CONFIG")
	}
	if path == "" {
		path = "/etc/krb5.conf"
	}
	kc, e := kconfig.Load(path)
	if e != nil {
		return nil, fmt.Errorf("Kerberos configuration: %w", e)
	}
	return &krb5.Config{KRB5Config: krb5.ParsedLibDefaults(kc), DCEStyle: true, DisablePAFXFAST: true, KDCDialer: auth.NewKDCDialer(ctx, cfg.Timeout)}, nil
}
func (c *Client) Close() { c.sockets.close(); c.conn.Close(context.Background()) }
func (c *Client) Zones(ctx context.Context) ([]string, error) {
	stop := context.AfterFunc(ctx, c.sockets.close)
	defer stop()
	r, err := c.rpc.ComplexOperation2(ctx, &dnsserver.ComplexOperation2Request{ServerName: c.server, Operation: "EnumZones", TypeIn: uint32(dnsp.TypeIDDword), DataIn: &dnsp.Union{Value: &dnsp.Union_Dword{Dword: uint32(dnsp.ZoneRequestFilterPrimary)}}})
	if err != nil {
		return nil, fmt.Errorf("DNS enumerate zones: %w", err)
	}
	if r.Return != 0 {
		return nil, fmt.Errorf("DNS enumerate zones: status %d", r.Return)
	}
	if r.DataOut == nil {
		return nil, errors.New("DNS enumerate zones: missing result")
	}
	list, ok := r.DataOut.GetValue().(*dnsp.ZoneListW2K)
	if !ok {
		return nil, fmt.Errorf("DNS enumerate zones: unexpected result type %d", r.TypeOut)
	}
	zones := make([]string, 0, len(list.ZoneArray))
	for _, z := range list.ZoneArray {
		if z != nil {
			zones = append(zones, z.ZoneName)
		}
	}
	sort.Strings(zones)
	return zones, nil
}

// Records enumerates the management interface, not ordinary DNS answers. A
// partial/overflow response is an error, never a successful partial zone.
func (c *Client) Records(ctx context.Context, zone, node string, typ uint16) ([]Row, error) {
	if node == "" {
		node = "@"
	}
	if typ == 0 {
		typ = dns.TypeANY
	}
	stop := context.AfterFunc(ctx, c.sockets.close)
	defer stop()
	queue := []string{node}
	visited := map[string]bool{}
	rows := []Row{}
	size := 0
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		parent := queue[0]
		queue = queue[1:]
		if visited[parent] {
			continue
		}
		visited[parent] = true
		if len(visited) > 10000 {
			return nil, errors.New("DNS enumeration exceeds 10000 nodes")
		}
		r, err := c.rpc.EnumRecords2(ctx, &dnsserver.EnumRecords2Request{ClientVersion: 0x70000, ServerName: c.server, Zone: zone, NodeName: parent, RecordType: typ, SelectFlag: 1})
		if err != nil {
			return nil, fmt.Errorf("DNS enumerate records: %w", err)
		}
		if r.Return != 0 {
			return nil, statusError("enumerate records", r.Return)
		}
		size += len(r.Buffer)
		if size > 16<<20 {
			return nil, errors.New("DNS record response exceeds 16 MiB (no partial results accepted)")
		}
		nodes, err := decodeNodes(r.Buffer)
		if err != nil {
			return nil, fmt.Errorf("DNS record decoding: %w", err)
		}
		for _, n := range nodes.DNSNodes {
			if n == nil || n.DNSNodeName == nil {
				return nil, errors.New("DNS record decoding: missing node")
			}
			label := strings.TrimRight(string(n.DNSNodeName.DNSName), "\x00")
			name := label
			if label == "" {
				name = parent
			} else if parent != "@" {
				name = label + "." + parent
			}
			if label != "" && n.ChildCount > 0 {
				queue = append(queue, name)
			}
			for _, rec := range n.DNSRecords {
				rr, err := decodeRecord(rec)
				if err != nil {
					return nil, err
				}
				rr.Header().Name = "."
				parts := strings.SplitN(rr.String(), "\t", 5)
				if len(parts) != 5 {
					return nil, errors.New("DNS record decoding: invalid resource record")
				}
				row := Row{Name: name, Type: dns.TypeToString[rr.Header().Rrtype], Value: parts[4], TTL: rr.Header().Ttl, Flags: rec.Flags, Serial: rec.Serial, Timestamp: rec.Timestamp}
				// A parent's response already contains its immediate children's records.
				// The recursive response's self node must not duplicate those records.
				if parent == node || label != "" {
					rows = append(rows, row)
				}
			}
		}
	}
	return rows, nil
}

// Replace matches the old RDATA on this DC and preserves its existing TTL,
// rank/flags and aging metadata, as Samba's management update does. The only
// write is a single add+delete request; reads are not a write retry or rollback.
func (c *Client) Replace(ctx context.Context, zone, name string, old, new *record.Record) error {
	if old == nil || new == nil {
		return errors.New("replace requires old and new records")
	}
	rr, e := decodeRecord(old)
	if e != nil {
		return e
	}
	rr.Header().Name = "."
	rows, e := c.Records(ctx, zone, name, uint16(old.Type))
	if e != nil {
		return e
	}
	for _, row := range rows {
		candidate, e := dns.NewRR(fmt.Sprintf(". %d IN %s %s", row.TTL, row.Type, row.Value))
		if e != nil {
			return fmt.Errorf("DNS update parse observed record: %w", e)
		}
		if dns.IsDuplicate(rr, candidate) {
			original := *old
			replacement := *new
			original.TTLSeconds = row.TTL
			original.Flags = row.Flags
			original.Serial = row.Serial
			original.Timestamp = row.Timestamp
			replacement.TTLSeconds = row.TTL
			replacement.Flags = row.Flags
			replacement.Serial = row.Serial
			replacement.Timestamp = row.Timestamp
			return c.Mutate(ctx, zone, name, &original, &replacement)
		}
	}
	return &StatusError{Operation: "update old record no longer matches; refresh", Code: 9714}
}

// Mutate performs exactly one RPC request. old/new nil mean add/delete. An
// exchange sends both records in the same server operation, not delete+add.
// Transport failures after dispatch have uncertain outcomes, not rollback.
func (c *Client) Mutate(ctx context.Context, zone, name string, old, new *record.Record) error {
	if old == nil && new == nil {
		return errors.New("empty DNS mutation")
	}
	convert := func(r *record.Record) (*dnsp.Record, error) {
		if r == nil {
			return nil, nil
		}
		b, e := ndr.Marshal(r, ndr.Opaque)
		if e != nil {
			return nil, e
		}
		var out dnsp.Record
		if e = ndr.Unmarshal(b, &out, ndr.Opaque); e != nil {
			return nil, e
		}
		return &out, nil
	}
	add, e := convert(new)
	if e != nil {
		return e
	}
	del, e := convert(old)
	if e != nil {
		return e
	}
	stop := context.AfterFunc(ctx, c.sockets.close)
	defer stop()
	if err := ctx.Err(); err != nil {
		return err
	}
	r, e := c.rpc.UpdateRecord2(ctx, &dnsserver.UpdateRecord2Request{ServerName: c.server, Zone: zone, NodeName: name, AddRecord: add, DeleteRecord: del})
	if e != nil {
		return &UncertainError{Cause: e}
	}
	if r.Return != 0 {
		return statusError("write", r.Return)
	}
	return nil
}
