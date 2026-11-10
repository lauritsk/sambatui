package config

import "errors"

func (settings Settings) validateSize() error {
	remainingBytes := configBytesMax
	for _, value := range []string{
		settings.Server, settings.Domain, settings.LastZone, settings.User,
		settings.Auth, settings.DNSAuth, settings.Cache, settings.KerberosConfig,
		settings.BaseDN, settings.Encryption, settings.CAFile, settings.PasswordFile,
		settings.AutoPTR,
	} {
		if len(value) > remainingBytes {
			return errors.New("configuration values exceed 1 MiB")
		}
		remainingBytes -= len(value)
	}
	if len(settings.Password.Reveal()) > passwordLineBytesMax {
		return errors.New("password exceeds 1 MiB")
	}
	return nil
}
