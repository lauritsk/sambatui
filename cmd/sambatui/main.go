package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/journal"
	"github.com/lauritsk/sambatui/internal/tui"
)

var version = "development"

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "sambatui:", tui.Literal(e.Error()))
		os.Exit(1)
	}
}

func run() error {
	path, e := config.DefaultPath()
	if e != nil {
		return e
	}
	configPath := flag.String("config", path, "native JSON preferences path (password stored separately)")
	showVersion := flag.Bool("version", false, "show version")
	check := flag.Bool("check", false, "check authentication, enumerate zones and verify LDAP TLS/bind without writes")
	flag.Parse()
	if *showVersion {
		fmt.Println("sambatui", version)
		return nil
	}
	s, e := config.Load(*configPath, os.LookupEnv)
	if e != nil {
		return e
	}
	redact := func(e error) error {
		if e == nil {
			return nil
		}
		v := e.Error()
		if password := s.Password.Reveal(); password != "" {
			v = strings.ReplaceAll(v, password, "[redacted]")
		}
		return fmt.Errorf("%s", v)
	}
	if *check {
		if e = s.Validate(true); e != nil {
			return redact(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.TimeoutSeconds)*time.Second)
		defer cancel()
		zones, e := (backend.Native{}).Zones(ctx, s)
		if e != nil {
			return redact(e)
		}
		if e = directory.New(s.LDAP()).Check(ctx); e != nil {
			return redact(e)
		}
		fmt.Printf("Authenticated DNS management: %d zones; certificate-verified LDAP bind succeeded. No writes performed.\n", len(zones))
		return nil
	}
	store, e := journal.Open(*configPath)
	if e != nil {
		return e
	}
	defer store.Close()
	model := tui.New(s, *configPath, nil)
	if e = model.UseJournal(store); e != nil {
		return e
	}
	_, e = tea.NewProgram(model, tea.WithAltScreen()).Run()
	return redact(e)
}
