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
	if cert == nil || len(cert.Raw) == 0 {
		return nil, errors.New("missing TLS certificate for channel binding")
	}
	var digest []byte
	switch cert.SignatureAlgorithm {
	case x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1,
		x509.ECDSAWithSHA1, x509.SHA256WithRSA, x509.SHA256WithRSAPSS,
		x509.DSAWithSHA256, x509.ECDSAWithSHA256:
		hash := sha256.Sum256(cert.Raw)
		digest = hash[:]
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		hash := sha512.Sum384(cert.Raw)
		digest = hash[:]
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		hash := sha512.Sum512(cert.Raw)
		digest = hash[:]
	default:
		return nil, errors.New("unsupported TLS certificate signature for channel binding")
	}
	app := append([]byte("tls-server-end-point:"), digest...)
	data := make([]byte, 20+len(app))
	binary.LittleEndian.PutUint32(data[16:20], uint32(len(app)))
	copy(data[20:], app)
	return data, nil
}

func bindingHash(binding []byte) []byte {
	hash := md5.Sum(binding)
	return hash[:]
}
