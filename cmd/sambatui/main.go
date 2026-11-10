package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/journal"
	"github.com/lauritsk/sambatui/internal/tui"
)

var version = "development"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sambatui:", tui.Literal(err.Error()))
		os.Exit(1)
	}
}

func run() error {
	path, err := config.DefaultPath()
	if err != nil {
		return err
	}
	configPath := flag.String(
		"config",
		path,
		"native JSON preferences path (password stored separately)",
	)
	showVersion := flag.Bool("version", false, "show version")
	flag.Parse()
	if *showVersion {
		fmt.Println("sambatui", version)
		return nil
	}
	settings, err := config.Load(*configPath, os.LookupEnv)
	if err != nil {
		return err
	}
	redact := func(err error) error {
		if err == nil {
			return nil
		}
		value := err.Error()
		if password := settings.Password.Reveal(); password != "" {
			value = strings.ReplaceAll(value, password, "[redacted]")
		}
		return fmt.Errorf("%s", value)
	}
	store, err := journal.Open(*configPath)
	if err != nil {
		return err
	}
	defer store.Close()
	model := tui.New(settings, *configPath, nil)
	if err = model.UseJournal(store); err != nil {
		return err
	}
	_, err = tea.NewProgram(model, tea.WithAltScreen()).Run()
	return redact(err)
}
