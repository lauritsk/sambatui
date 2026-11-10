package dnsrpc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lauritsk/sambatui/internal/auth"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/krb5"
	"github.com/oiweiwei/gokrb5.fork/v9/client"
	"github.com/oiweiwei/gokrb5.fork/v9/credentials"
)

// The RPC provider does not expose client.Destroy. Give it only the exact
// service ticket, not a password/TGT that could start an unowned renewal
// goroutine. Our ticket-acquisition client is always destroyed here.
func serviceCredential(ctx context.Context, cfg Config, k *krb5.Config) (credential.CCache, error) {
	if os.Getenv("KRB5_CCACHE") != "" {
		return nil, errors.New("unset nonstandard KRB5_CCACHE; select the cache explicitly with SAMBATUI_KRB5_CCACHE")
	}
	var cl *client.Client
	var e error
	settings := []func(*client.Settings){client.DisablePAFXFAST(true), client.Dialer(auth.NewKDCDialer(ctx, cfg.Timeout))}
	if cfg.Auth == "kerberos" {
		cache, e := auth.LoadCache(cfg.Cache, cfg.CacheContents)
		if e != nil {
			return nil, e
		}
		cl, e = client.NewFromCCacheOptionalTGT(cache, k.GetKRB5Config(), settings...)
	} else {
		c := credential.NewFromPassword(cfg.User, cfg.Password.Reveal())
		cl = client.NewWithPassword(c.UserName(), c.DomainName(), c.Password(), k.GetKRB5Config(), settings...)
	}
	if e != nil {
		return nil, e
	}
	defer cl.Destroy()
	if cfg.Auth != "kerberos" {
		if e = cl.AffirmLogin(); e != nil {
			return nil, fmt.Errorf("DNS Kerberos password authentication: %w", e)
		}
	}
	tkt, key, e := cl.GetServiceTicket("DNS/" + cfg.Server)
	if e != nil {
		return nil, fmt.Errorf("DNS Kerberos service ticket: %w", e)
	}
	ticket, e := tkt.Marshal()
	if e != nil {
		return nil, e
	}
	p := credentials.Principal{Realm: cl.Credentials.Domain(), PrincipalName: cl.Credentials.CName()}
	now := time.Now().UTC()
	// Local cache validity is short-lived; the actual KDC-signed ticket expiry
	// remains authoritative and is verified by the DC during authentication.
	cc := &credentials.CCache{Version: 4, DefaultPrincipal: p, Credentials: []*credentials.Credential{{Client: p, Server: credentials.Principal{Realm: tkt.Realm, PrincipalName: tkt.SName}, Key: key, AuthTime: now.Add(-time.Second), StartTime: now.Add(-time.Second), EndTime: now.Add(time.Minute), Ticket: ticket}}}
	principal := strings.Join(p.PrincipalName.NameString, "/") + "@" + p.Realm
	return credential.NewFromCCache(principal, cc), nil
}
