package auth

import (
	"bytes"
	"fmt"
	"os"

	"github.com/lauritsk/sambatui/internal/configfile"
	"github.com/oiweiwei/gokrb5.fork/v9/config"
)

const kerberosConfigBytesMax = 1 << 20

// Resolve defaults only at the configuration boundary, then bound the parser's
// input. The dependency retains all lines, so Scanner's line limit is not enough.
func LoadKerberosConfig(path string) (*config.Config, error) {
	if path == "" {
		path = os.Getenv("KRB5_CONFIG")
	}
	if path == "" {
		path = "/etc/krb5.conf"
	}
	data, err := configfile.Read(path, kerberosConfigBytesMax)
	if err != nil {
		return nil, fmt.Errorf("Kerberos configuration: %w", err)
	}
	settings, err := config.NewFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("Kerberos configuration: %w", err)
	}
	return settings, nil
}
