package directory

import (
	"crypto/md5"
	"errors"
	"strings"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/gofork/encoding/asn1"
	"github.com/lauritsk/sambatui/internal/auth"
)

// Integrated authentication is explicitly selected; never fall back to SIMPLE.
func bindNTLMClient(
	user string, password auth.Secret, target string, binding []byte,
) (*ntlmssp.Client, []byte, error) {
	domain, username, ok := strings.Cut(user, `\`)
	if !ok || username == "" {
		return nil, nil, errors.New("NTLM requires DOMAIN\\\\user")
	}
	client := &ntlmssp.Client{
		Domain:     domain,
		User:       username,
		Password:   password.Reveal(),
		TargetSPN:  target,
		StripFlags: ntlmssp.FlgNegSign | ntlmssp.FlgNegSeal | ntlmssp.FlgNegKeyExch,
	}
	client.SetChannelBindingHash(md5.Sum(binding))
	token, err := client.Negotiate()
	if err != nil {
		return nil, nil, err
	}
	out, err := gss.NewNegTokenInit([]asn1.ObjectIdentifier{gss.NtLmSSPMechTypeOid}, token)
	if err != nil {
		return nil, nil, err
	}
	return client, out, nil
}
