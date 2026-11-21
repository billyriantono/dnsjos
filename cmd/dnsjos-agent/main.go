// dnsjos-agent runs on every dnsdist node (SPEC §9) and, in recursor mode, on every
// recursor host (SPEC §20).
//
//	dnsjos-agent enroll --panel URL --token T [--name NAME] [--adopt]
//	dnsjos-agent enroll --recursor --kind pdns|unbound --panel URL --token T [--name NAME]
//	dnsjos-agent [run] [--root DIR] [--no-systemd] [--dnsdist-web URL] [--flush-interval D]
//	dnsjos-agent plan [--root DIR] [--no-systemd]
//	dnsjos-agent tproxy-relay --port 5300 --dnsdist 127.0.0.1:5301
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
	"github.com/billyriantono/dnsjos/internal/agent/tproxy"
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
	fs.DurationVar(&o.FlushInterval, "flush-interval", 0, "test mode: how often blocked and analytics windows are posted (default 60s)")
	level := fs.String("log-level", "info", "debug|info|warn|error")
	var panel, token, name string
	var adopt, recursor bool
	var kind string
	var relayPort int
	var relayBackend string
	if cmd == "enroll" {
		fs.BoolVar(&recursor, "recursor", false, "enroll this host as a recursor (PowerDNS Recursor or Unbound), not a dnsdist node")
		fs.StringVar(&kind, "kind", "", "recursor only: the resolver installed here, pdns or unbound")
		fs.BoolVar(&adopt, "adopt", false, "take over the live dnsdist_ootb server: import its secrets and listeners")
		fs.StringVar(&panel, "panel", "", "panel URL, e.g. https://panel.example")
		fs.StringVar(&token, "token", "", "enrollment token")
		fs.StringVar(&name, "name", "", "hostname to report (default: this host's name)")
	}
	if cmd == "tproxy-relay" {
		fs.IntVar(&relayPort, "port", 5300, "transparent TPROXY port")
		fs.StringVar(&relayBackend, "dnsdist", "127.0.0.1:5301", "loopback dnsdist listener with PROXY protocol")
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
		if recursor {
			err = agent.EnrollRecursor(ctx, o, panel, token, kind, name)
		} else {
			err = agent.Enroll(ctx, o, panel, token, name, adopt)
		}
	case "plan":
		err = agent.Plan(ctx, o, os.Stdout)
	case "tproxy-relay":
		err = tproxy.RunRelay(ctx, tproxy.RelayConfig{Port: relayPort, DNSDistAddr: relayBackend, Log: o.Log})
	case "run":
		if agent.IsRecursor(o) {
			err = agent.RunRecursor(ctx, o)
		} else {
			err = agent.Run(ctx, o)
		}
	default:
		err = fmt.Errorf("unknown command %q (enroll | plan | run | tproxy-relay | version)", cmd)
	}
	if err != nil {
		o.Log.Error(err.Error())
		os.Exit(1)
	}
}
