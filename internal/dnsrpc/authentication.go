package dnsrpc

import (
	"context"
	"errors"
	"os"

	"github.com/lauritsk/sambatui/internal/auth"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/oiweiwei/go-msrpc/ssp/krb5"
)

func dialAuthentication(
	operationContext context.Context,
	settings Config,
) ([]gssapi.ContextOption, error) {
	var opts []gssapi.ContextOption
	switch settings.Auth {
	case "", "password":
		if settings.User == "" || settings.Password.Reveal() == "" {
			return nil, errors.New("DNS requires username and password")
		}
		mechanism := gssapi.WithMechanismFactory(ssp.NTLM)
		if settings.PasswordAuth == "kerberos" {
			kerberosConfig, err := kerberosSettings(operationContext, settings)
			if err != nil {
				return nil, err
			}
			currentCredential, err := serviceCredential(operationContext, settings, kerberosConfig)
			if err != nil {
				return nil, err
			}
			opts = []gssapi.ContextOption{
				gssapi.WithCredential(currentCredential),
				gssapi.WithMechanismFactory(ssp.KRB5, kerberosConfig),
			}
			mechanism = nil
		} else if settings.PasswordAuth != "" && settings.PasswordAuth != "ntlm" {
			return nil, errors.New("DNS password auth must be ntlm or kerberos")
		}
		if mechanism != nil {
			opts = []gssapi.ContextOption{
				gssapi.WithCredential(
					credential.NewFromPassword(settings.User, settings.Password.Reveal()),
				),
				mechanism,
			}
		}
	case "kerberos":
		// Load first so a missing explicit selector fails before any network IO.
		if _, err := auth.LoadCache(settings.Cache, settings.CacheContents); err != nil {
			return nil, err
		}
		kerberosConfig, err := kerberosSettings(operationContext, settings)
		if err != nil {
			return nil, err
		}
		currentCredential, err := serviceCredential(operationContext, settings, kerberosConfig)
		if err != nil {
			return nil, err
		}
		opts = []gssapi.ContextOption{
			gssapi.WithCredential(currentCredential),
			gssapi.WithMechanismFactory(ssp.KRB5, kerberosConfig),
		}
	default:
		return nil, errors.New("DNS auth must be password or kerberos")
	}
	// The upstream provider also recognizes a nonstandard ambient variable.
	// Reject it rather than allowing it to seed a different principal's TGT.
	if (settings.Auth == "kerberos" || settings.PasswordAuth == "kerberos") &&
		os.Getenv("KRB5_CCACHE") != "" {
		return nil, errors.New(
			"unset nonstandard KRB5_CCACHE; select the cache explicitly " +
				"with SAMBATUI_KRB5_CCACHE",
		)
	}
	return opts, nil
}

func kerberosSettings(operationContext context.Context, settings Config) (*krb5.Config, error) {
	kerberosConfig, err := auth.LoadKerberosConfig(settings.KerberosConfig)
	if err != nil {
		return nil, err
	}
	return &krb5.Config{
		KRB5Config:      krb5.ParsedLibDefaults(kerberosConfig),
		DCEStyle:        true,
		DisablePAFXFAST: true,
		KDCDialer:       auth.NewKDCDialer(operationContext, settings.Timeout),
	}, nil
}
