// Package config reads the panel configuration from the environment (SPEC §15).
package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Listen        string
	DatabaseURL   string
	DataDir       string
	PublicURL     string // no trailing slash
	SecureCookies bool
	LogLevel      slog.Level

	BrandName, BrandTagline string // DNSJOS_BRAND_NAME (default DnsJos), DNSJOS_BRAND_TAGLINE
	BrandDir                string // DNSJOS_BRAND_DIR (default $DATA_DIR/branding)

	BootstrapAdminEmail    string
	BootstrapAdminPassword string
}

func Load() (Config, error) {
	c := Config{
		Listen:                 env("DNSJOS_LISTEN", "127.0.0.1:8080"),
		DatabaseURL:            env("DNSJOS_DATABASE_URL", "postgres://dnsjos@127.0.0.1:5432/dnsjos?sslmode=disable"),
		DataDir:                env("DNSJOS_DATA_DIR", "/var/lib/dnsjos"),
		PublicURL:              strings.TrimRight(env("DNSJOS_PUBLIC_URL", "http://127.0.0.1:8080"), "/"),
		BootstrapAdminEmail:    os.Getenv("DNSJOS_BOOTSTRAP_ADMIN_EMAIL"),
		BootstrapAdminPassword: os.Getenv("DNSJOS_BOOTSTRAP_ADMIN_PASSWORD"),
		BrandName:              env("DNSJOS_BRAND_NAME", "DnsJos"),
		BrandTagline:           os.Getenv("DNSJOS_BRAND_TAGLINE"),
	}
	c.BrandDir = env("DNSJOS_BRAND_DIR", filepath.Join(c.DataDir, "branding"))
	u, err := url.Parse(c.PublicURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return c, fmt.Errorf("DNSJOS_PUBLIC_URL: %q is not an http(s) URL", c.PublicURL)
	}
	switch v := env("DNSJOS_SECURE_COOKIES", "auto"); v {
	case "auto":
		c.SecureCookies = u.Scheme == "https"
	default:
		if c.SecureCookies, err = strconv.ParseBool(v); err != nil {
			return c, fmt.Errorf("DNSJOS_SECURE_COOKIES: %q is not auto|true|false", v)
		}
	}
	if err := c.LogLevel.UnmarshalText([]byte(env("DNSJOS_LOG_LEVEL", "info"))); err != nil {
		return c, fmt.Errorf("DNSJOS_LOG_LEVEL: %w", err)
	}
	return c, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
