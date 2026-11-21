//go:build !linux

package tproxy

import (
	"context"
	"errors"
	"log/slog"
)

// RelayConfig configures the transparent relay. TPROXY mode is Linux-only.
type RelayConfig struct {
	Port        int
	DNSDistAddr string
	Log         *slog.Logger
}

// RunRelay is unsupported off Linux.
func RunRelay(context.Context, RelayConfig) error {
	return errors.New("tproxy relay: only supported on Linux")
}
