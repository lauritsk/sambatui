package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lauritsk/sambatui/internal/devtool"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "dev:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	const usage = "usage: go run ./cmd/dev check|release|integration [options]"
	if len(arguments) == 0 {
		return errors.New(usage)
	}
	if arguments[0] == "--help" || arguments[0] == "-h" || arguments[0] == "help" {
		fmt.Fprintln(os.Stdout, usage)
		return nil
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	tools, err := devtool.New(root, os.Stdout)
	if err != nil {
		return err
	}
	interrupted, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(interrupted, 20*time.Minute)
	defer cancel()

	switch arguments[0] {
	case "check":
		if len(arguments) != 1 {
			return errors.New("check takes no arguments")
		}
		return tools.Check(ctx)
	case "release":
		options := flag.NewFlagSet("release", flag.ContinueOnError)
		version := options.String("version", "", "required release version (1–64 ASCII characters)")
		output := options.String("output", "dist", "new artifact directory; must not already exist")
		if err := options.Parse(arguments[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if options.NArg() != 0 {
			return errors.New("release takes named options only")
		}
		return tools.Release(ctx, *version, *output)
	case "integration":
		if len(arguments) != 1 {
			return errors.New("integration takes no arguments; use SAMBATUI_TEST_SERVER_IMAGE")
		}
		return tools.Integration(ctx, os.Getenv("SAMBATUI_TEST_SERVER_IMAGE"))
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}
