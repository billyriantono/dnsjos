// dnsjos-agent runs on every dnsdist node (SPEC §9).
//
//	dnsjos-agent enroll --panel URL --token T [--name NAME] [--adopt]
//	dnsjos-agent [run] [--root DIR] [--no-systemd] [--dnsdist-web URL]
//	dnsjos-agent plan [--root DIR] [--no-systemd]
//	dnsjos-agent version
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/billyriantono/dnsjos/internal/agent"
)

var version = "dev"

func main() {
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("dnsjos-agent "+cmd, flag.ExitOnError)
	var o agent.Options
	fs.StringVar(&o.Root, "root", "", "test mode: prefix every filesystem path with DIR")
	fs.BoolVar(&o.NoSystemd, "no-systemd", false, "test mode: skip systemctl; tolerate a missing dnsdist binary")
	fs.StringVar(&o.DnsdistWeb, "dnsdist-web", "", "dnsdist webserver URL (default: http://<spec.webserver.listen>)")
	level := fs.String("log-level", "info", "debug|info|warn|error")
	var panel, token, name string
	var adopt bool
	if cmd == "enroll" {
		fs.BoolVar(&adopt, "adopt", false, "take over the live dnsdist_ootb server: import its secrets and listeners")
		fs.StringVar(&panel, "panel", "", "panel URL, e.g. https://panel.example")
		fs.StringVar(&token, "token", "", "enrollment token")
		fs.StringVar(&name, "name", "", "hostname to report (default: this host's name)")
	}
	fs.Parse(args)

	var lv slog.Level
	lv.UnmarshalText([]byte(*level))
	o.Log = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))
	o.Version = version

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var err error
	switch cmd {
	case "version":
		fmt.Println(version)
	case "enroll":
		err = agent.Enroll(ctx, o, panel, token, name, adopt)
	case "plan":
		err = agent.Plan(ctx, o, os.Stdout)
	case "run":
		err = agent.Run(ctx, o)
	default:
		err = fmt.Errorf("unknown command %q (enroll | plan | run | version)", cmd)
	}
	if err != nil {
		o.Log.Error(err.Error())
		os.Exit(1)
	}
}
