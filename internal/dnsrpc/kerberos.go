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
	"github.com/oiweiwei/gokrb5.fork/v9/messages"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
)

// The RPC provider does not expose client.Destroy. Give it only the exact
// service ticket, not a password/TGT that could start an unowned renewal
// goroutine. Our ticket-acquisition client is always destroyed here.
func serviceCredential(
	operationContext context.Context,
	connectionSettings Config,
	kerberosConfig *krb5.Config,
) (credential.CCache, error) {
	if os.Getenv("KRB5_CCACHE") != "" {
		return nil, errors.New(
			"unset nonstandard KRB5_CCACHE; select the cache explicitly " +
				"with SAMBATUI_KRB5_CCACHE",
		)
	}
	var kerberosClient *client.Client
	var err error
	clientOptions := []func(*client.Settings){
		client.DisablePAFXFAST(true),
		client.Dialer(auth.NewKDCDialer(operationContext, connectionSettings.Timeout)),
	}
	if connectionSettings.Auth == "kerberos" {
		cache, err := auth.LoadCache(connectionSettings.Cache, connectionSettings.CacheContents)
		if err != nil {
			return nil, err
		}
		kerberosClient, err = client.NewFromCCacheOptionalTGT(
			cache,
			kerberosConfig.GetKRB5Config(),
			clientOptions...,
		)
	} else {
		passwordCredential := credential.NewFromPassword(
			connectionSettings.User, connectionSettings.Password.Reveal(),
		)
		kerberosClient = client.NewWithPassword(
			passwordCredential.UserName(),
			passwordCredential.DomainName(),
			passwordCredential.Password(),
			kerberosConfig.GetKRB5Config(),
			clientOptions...,
		)
	}
	if err != nil {
		return nil, err
	}
	defer kerberosClient.Destroy()
	if connectionSettings.Auth != "kerberos" {
		if err = kerberosClient.AffirmLogin(); err != nil {
			return nil, fmt.Errorf("DNS Kerberos password authentication: %w", err)
		}
	}
	serviceTicket, key, err := kerberosClient.GetServiceTicket("DNS/" + connectionSettings.Server)
	if err != nil {
		return nil, fmt.Errorf("DNS Kerberos service ticket: %w", err)
	}
	ticket, err := serviceTicket.Marshal()
	if err != nil {
		return nil, err
	}
	return serviceCache(kerberosClient, serviceTicket, key, ticket), nil
}

func serviceCache(
	kerberosClient *client.Client, serviceTicket messages.Ticket,
	key types.EncryptionKey, ticket []byte,
) credential.CCache {
	currentPrincipal := credentials.Principal{
		Realm:         kerberosClient.Credentials.Domain(),
		PrincipalName: kerberosClient.Credentials.CName(),
	}
	now := time.Now().UTC()
	// Local cache validity is short-lived; the actual KDC-signed ticket expiry
	// remains authoritative and is verified by the DC during authentication.
	cache := &credentials.CCache{
		Version:          4,
		DefaultPrincipal: currentPrincipal,
		Credentials: []*credentials.Credential{
			{
				Client: currentPrincipal,
				Server: credentials.Principal{
					Realm:         serviceTicket.Realm,
					PrincipalName: serviceTicket.SName,
				},
				Key:       key,
				AuthTime:  now.Add(-time.Second),
				StartTime: now.Add(-time.Second),
				EndTime:   now.Add(time.Minute),
				Ticket:    ticket,
			},
		},
	}
	principal := strings.Join(currentPrincipal.PrincipalName.NameString, "/") + "@" +
		currentPrincipal.Realm
	return credential.NewFromCCache(principal, cache)
}
