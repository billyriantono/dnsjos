package cdb

import (
	"net/netip"
	"testing"
)

func TestDomainKey(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":                     "\x07example\x03com\x00",
		"Example.COM.":                    "\x07example\x03com\x00",
		"a.b-c.xn--p1ai":                  "\x01a\x03b-c\x08xn--p1ai\x00",
		"com":                             "\x03com\x00",
		"a..b":                            "\x01a\x01b\x00",
		"":                                "",
		".":                               "",
		string(make([]byte, 64)) + ".com": "",
	} {
		if got := string(DomainKey(in)); got != want {
			t.Errorf("DomainKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIPv4Key(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3.4":         "\x011\x012\x013\x014\x00",
		"192.168.10.255":  "\x03192\x03168\x0210\x03255\x00",
		"0.0.0.0":         "\x010\x010\x010\x010\x00",
		"::ffff:10.0.0.1": "\x0210\x010\x010\x011\x00",
	} {
		if got := string(IPv4Key(netip.MustParseAddr(in))); got != want {
			t.Errorf("IPv4Key(%s) = %q, want %q", in, got, want)
		}
	}
}
