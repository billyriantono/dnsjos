// Command dnsjos is the DnsJos control panel.
//
//	dnsjos [serve]                                   run the panel (default)
//	dnsjos migrate                                   apply database migrations and exit
//	dnsjos admin create --email E --password P [--name N]
//	dnsjos version
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/billyriantono/dnsjos/internal/panel/auth"
	"github.com/billyriantono/dnsjos/internal/panel/config"
	"github.com/billyriantono/dnsjos/internal/panel/db"
	"github.com/billyriantono/dnsjos/internal/panel/server"
)

var version = "dev" // set with -ldflags "-X main.version=…"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "dnsjos:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	if cmd == "version" {
		fmt.Println(version)
		return nil
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cmd {
	case "serve":
		return server.Run(ctx, cfg, log, version)
	case "migrate":
		pool, err := db.Connect(ctx, cfg.DatabaseURL)
		if err != nil {
			return err
		}
		defer pool.Close()
		applied, err := db.Migrate(ctx, pool)
		if err != nil {
			return err
		}
		fmt.Printf("applied %d migration(s) %v\n", len(applied), applied)
		return nil
	case "admin":
		if len(args) == 0 || args[0] != "create" {
			return fmt.Errorf("usage: dnsjos admin create --email E --password P [--name N]")
		}
		fs := flag.NewFlagSet("admin create", flag.ContinueOnError)
		email := fs.String("email", "", "admin email")
		password := fs.String("password", "", "admin password (8..72 bytes)")
		name := fs.String("name", "", "display name")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *email == "" || *password == "" {
			return fmt.Errorf("--email and --password are required")
		}
		pool, err := db.Connect(ctx, cfg.DatabaseURL)
		if err != nil {
			return err
		}
		defer pool.Close()
		if _, err := db.Migrate(ctx, pool); err != nil {
			return err
		}
		u, err := auth.CreateAdmin(ctx, pool, *email, *password, *name)
		if err != nil {
			return err
		}
		fmt.Printf("admin %s created (id %s)\n", u.Email, u.ID)
		return nil
	default:
		return fmt.Errorf("unknown command %q (serve, migrate, admin create, version)", cmd)
	}
}
