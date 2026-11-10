package auth

import (
	"crypto/md5" // RFC 4121 channel-binding digest, not a password hash.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
)

// ChannelBinding implements RFC 5929 tls-server-end-point and RFC 2744's
// GSS channel-bindings serialization. MD5/SHA1 signature algorithms upgrade to
// SHA256. Unknown certificate signature algorithms fail closed.
func ChannelBinding(cert *x509.Certificate) ([]byte, error) {
	var digest []byte
	switch cert.SignatureAlgorithm {
	case x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1, x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.DSAWithSHA256, x509.ECDSAWithSHA256:
		d := sha256.Sum256(cert.Raw)
		digest = d[:]
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		d := sha512.Sum384(cert.Raw)
		digest = d[:]
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		d := sha512.Sum512(cert.Raw)
		digest = d[:]
	default:
		return nil, errors.New("unsupported TLS certificate signature for channel binding")
	}
	app := append([]byte("tls-server-end-point:"), digest...)
	b := make([]byte, 20+len(app))
	binary.LittleEndian.PutUint32(b[16:20], uint32(len(app)))
	copy(b[20:], app)
	return b, nil
}
func bindingHash(binding []byte) []byte { d := md5.Sum(binding); return d[:] }
