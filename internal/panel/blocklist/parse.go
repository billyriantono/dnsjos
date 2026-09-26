// Package blocklist owns the blocklist sources, the builder (fetch → normalize → CDB),
// the build artifacts and their serving to agents (SPEC §7).
package blocklist

import (
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// stripLine drops comments and surrounding whitespace; "" means nothing to parse.
func stripLine(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, ";") {
		return ""
	}
	return s
}

// normalizeDomain lowercases s, strips scheme/path/port/"*."/trailing dot, converts
// IDN to punycode and validates it. ok=false means the entry is invalid.
func normalizeDomain(s string) (string, bool) {
	s = strings.ToLower(s)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?"); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "*."), ".")
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			a, err := idna.Lookup.ToASCII(s)
			if err != nil {
				return "", false
			}
			s = a
			break
		}
	}
	if len(s) == 0 || len(s) > 253 {
		return "", false
	}
	label := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '.':
			if label == 0 {
				return "", false
			}
			label = 0
			continue
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return "", false
		}
		if label++; label > 63 {
			return "", false
		}
	}
	return s, label > 0
}

// whitelisted reports whether name or one of its parent domains is in wl.
func whitelisted(wl map[string]struct{}, name string) bool {
	for {
		if _, ok := wl[name]; ok {
			return true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
	}
}

// eachIPv4 calls fn for the address, or every address of a CIDR up to /24 (256
// keys). ok=false for anything else (invalid, IPv6, larger than /24).
func eachIPv4(s string, fn func(netip.Addr)) bool {
	if strings.IndexByte(s, '/') >= 0 {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Unmap().Is4() {
			return false
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-p.Addr().BitLen()+32).Masked()
		if p.Bits() < 24 {
			return false
		}
		for a := p.Addr(); p.Contains(a); a = a.Next() {
			fn(a)
		}
		return true
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Unmap().Is4() {
		return false
	}
	fn(a.Unmap())
	return true
}
