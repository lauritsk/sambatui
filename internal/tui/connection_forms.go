package tui

import (
	"errors"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/discovery"
	"github.com/lauritsk/sambatui/internal/invariant"
)

const (
	connectionServerField = iota
	connectionDomainField
	connectionBaseField
	connectionAuthField
	connectionUserField
	connectionPasswordField
	connectionTLSField
	connectionCAField
	connectionCacheField
	connectionKerberosConfigField
	connectionPTRField
	connectionDNSAuthField
	connectionPasswordFileField
	connectionTimeoutField
	connectionFieldCount
)

func (model *Model) connectionForm() {
	settings := model.settings
	model.openForm(
		"Connection",
		"",
		connectionFields(settings),
		false,
		func(values []string) tea.Cmd {
			settings.Server = strings.TrimSpace(values[connectionServerField])
			settings.Domain = strings.TrimSpace(values[connectionDomainField])
			settings.Domain = strings.TrimRight(settings.Domain, ".")
			settings.BaseDN = strings.TrimSpace(values[connectionBaseField])
			settings.Auth = strings.TrimSpace(values[connectionAuthField])
			settings.User = strings.TrimSpace(values[connectionUserField])
			settings.Password = newSecret(values[connectionPasswordField])
			settings.Encryption = strings.TrimSpace(values[connectionTLSField])
			settings.CAFile = values[connectionCAField]
			settings.Cache = values[connectionCacheField]
			settings.KerberosConfig = values[connectionKerberosConfigField]
			settings.AutoPTR = values[connectionPTRField]
			settings.DNSAuth = values[connectionDNSAuthField]
			settings.PasswordFile = values[connectionPasswordFileField]
			timeout, err := parseSetting(values[connectionTimeoutField])
			if err != nil {
				model.error(errors.New("timeout must be 1–300 seconds"))
				return nil
			}
			settings.TimeoutSeconds = timeout
			if settings.BaseDN == "" && settings.Domain != "" {
				settings.BaseDN = "DC=" + strings.ReplaceAll(settings.Domain, ".", ",DC=")
			}
			var freezeErr error
			settings, freezeErr = settings.Freeze()
			if freezeErr != nil {
				model.error(freezeErr)
				return nil
			}
			if err := settings.Validate(true); err != nil {
				model.error(err)
				return nil
			}
			model.setConnection(settings)
			if err := config.Save(model.configPath, settings); err != nil {
				model.error(err)
			}
			return model.load("zones")
		},
	)
	if model.form != nil {
		model.form.VisibleFields = connectionFieldIndices
		model.form.setChoices(connectionAuthField, "password", "kerberos")
		model.form.setChoices(connectionTLSField, "ldaps", "starttls")
		model.form.setChoices(connectionPTRField, "off", "ask", "on")
		model.form.setChoices(connectionDNSAuthField, "ntlm", "kerberos")
	}
}

func connectionFields(settings config.Settings) []field {
	return []field{
		connectionServerField: {
			"DC hostname", settings.Server, false,
		},
		connectionDomainField: {
			"AD DNS domain", settings.Domain, false,
		},
		connectionBaseField: {
			"LDAP base DN", settings.BaseDN, false,
		},
		connectionAuthField: {
			"Authentication", settings.Auth, false,
		},
		connectionUserField: {
			"User", settings.User, false,
		},
		connectionPasswordField: {
			"Password", settings.Password, true,
		},
		connectionTLSField: {
			"LDAP TLS", settings.Encryption, false,
		},
		connectionCAField: {
			"CA file (optional)", settings.CAFile, false,
		},
		connectionCacheField: {
			"Kerberos FILE cache", settings.Cache, false,
		},
		connectionKerberosConfigField: {
			"Kerberos config file", settings.KerberosConfig, false,
		},
		connectionPTRField: {
			"PTR records", settings.AutoPTR, false,
		},
		connectionDNSAuthField: {
			"DNS authentication", settings.DNSAuth, false,
		},
		connectionPasswordFileField: {
			"Password file path", settings.PasswordFile, false,
		},
		connectionTimeoutField: {
			"Timeout seconds 1–300", formatSetting(settings.TimeoutSeconds), false,
		},
	}
}

func connectionFieldIndices(fields []field) []int {
	invariant.Require(len(fields) == connectionFieldCount, "connection field layout changed")
	kerberos := strings.TrimSpace(fields[connectionAuthField].text()) == "kerberos"
	dnsKerberos := fields[connectionDNSAuthField].text() == "kerberos"
	indices := make([]int, 0, len(fields))
	for index := range fields {
		switch index {
		case connectionUserField, connectionPasswordField,
			connectionDNSAuthField, connectionPasswordFileField:
			if kerberos {
				continue
			}
		case connectionCacheField:
			if !kerberos {
				continue
			}
		case connectionKerberosConfigField:
			if !kerberos && !dnsKerberos {
				continue
			}
		}
		indices = append(indices, index)
	}
	return indices
}

func (model *Model) discoverForm() tea.Cmd {
	model.openForm(
		"Discover AD services",
		"",
		[]field{{"AD DNS domain", model.settings.Domain, false}},
		false,
		func(values []string) tea.Cmd {
			domain, err := discovery.NormalizeDomain(values[0])
			if err != nil {
				model.error(err)
				return nil
			}
			return model.startDiscovery(domain, nil)
		},
	)
	return nil
}

func (model *Model) savePasswordForm() {
	model.openForm(
		"Save password file",
		"Destination: "+model.settings.PasswordFile+
			"\nUnencrypted, owner-readable only (0600).",
		[]field{{"Type yes to save", "", false}},
		false,
		func(values []string) tea.Cmd {
			if values[0] != "yes" {
				model.status = "Password not saved"
				return nil
			}
			err := config.SavePassword(model.settings.PasswordFile, model.settings.Password)
			if err != nil {
				model.error(err)
			} else {
				model.status = "Password saved privately"
			}
			return nil
		},
	)
}
