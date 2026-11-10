package tui

import (
	"context"
	"errors"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/discovery"
)

func (model *Model) connectionForm() {
	settings := model.settings
	model.openForm(
		"Connection settings",
		"Individual DC hostname required: revisions are DC-local. TLS "+
			"verification cannot be disabled.",
		[]field{
			{"DC hostname", settings.Server, false},
			{"AD DNS domain", settings.Domain, false},
			{"LDAP base DN", settings.BaseDN, false},
			{"Auth: password / kerberos", settings.Auth, false},
			{"User (UPN/DN or DOMAIN\\user)", settings.User, false},
			{"Password (whitespace preserved)", settings.Password, true},
			{"TLS: ldaps / starttls", settings.Encryption, false},
			{"CA PEM file (empty = system roots)", settings.CAFile, false},
			{"Selected Kerberos FILE cache", settings.Cache, false},
			{"Kerberos config file", settings.KerberosConfig, false},
			{"PTR: off / ask / on", settings.AutoPTR, false},
			{"DNS password auth: ntlm / kerberos", settings.DNSAuth, false},
			{"Password file path", settings.PasswordFile, false},
			{"Timeout seconds 1–300", formatSetting(settings.TimeoutSeconds), false},
		},
		false,
		func(values []string) tea.Cmd {
			settings.Server = strings.TrimSpace(values[0])
			settings.Domain = strings.TrimRight(strings.TrimSpace(values[1]), ".")
			settings.BaseDN = strings.TrimSpace(values[2])
			settings.Auth = strings.TrimSpace(values[3])
			settings.User = strings.TrimSpace(values[4])
			settings.Password = newSecret(values[5])
			settings.Encryption = strings.TrimSpace(values[6])
			settings.CAFile = values[7]
			settings.Cache = values[8]
			settings.KerberosConfig = values[9]
			settings.AutoPTR = values[10]
			settings.DNSAuth = values[11]
			settings.PasswordFile = values[12]
			timeout, err := parseSetting(values[13])
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
}

func (model *Model) discoverForm() tea.Cmd {
	model.openForm(
		"Discover AD services",
		"Uses AD LDAP/Kerberos SRV queries; does not change an active "+
			"connection automatically.",
		[]field{{"AD DNS domain", model.settings.Domain, false}},
		false,
		func(values []string) tea.Cmd {
			domain, err := discovery.NormalizeDomain(values[0])
			if err != nil {
				model.error(err)
				return nil
			}
			snap := model.state.Snapshot()
			return func() tea.Msg {
				operationContext, cancel := context.WithTimeout(
					context.Background(),
					10*time.Second,
				)
				defer cancel()
				services, err := discovery.Discover(operationContext, domain, nil)
				return discovered{snap.Generation, domain, services, err}
			}
		},
	)
	return nil
}

func (model *Model) savePasswordForm() {
	model.openForm(
		"Save password file",
		"Destination: "+model.settings.PasswordFile+
			"\nStored unencrypted with mode 0600. Preferences never "+
			"contain the password.",
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
