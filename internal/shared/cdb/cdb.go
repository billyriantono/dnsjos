// Package cdb encodes blocklist keys the way dnsdist's CDB lookups expect them:
// DNS wire format, lowercase (KeyValueLookupKeySuffix/QName with wireFormat=true).
package cdb

import (
	"net/netip"
	"strconv"
	"strings"
)

// DomainKey returns the lowercase wire form of name, e.g. example.com →
// "\x07example\x03com\x00". Empty labels are skipped (as the production script
// does); nil means a label is longer than 63 bytes or the name has no labels.
func DomainKey(name string) []byte {
	name = strings.ToLower(name)
	key := make([]byte, 0, len(name)+2)
	for label := range strings.SplitSeq(name, ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			return nil
		}
		key = append(key, byte(len(label)))
		key = append(key, label...)
	}
	if len(key) == 0 {
		return nil
	}
	return append(key, 0)
}

// IPv4Key returns the dotted quad as wire-format labels, e.g. 1.2.3.4 →
// "\x011\x012\x013\x014\x00". ip must be IPv4 (or IPv4-mapped IPv6).
func IPv4Key(ip netip.Addr) []byte {
	a := ip.Unmap().As4()
	key := make([]byte, 0, 17)
	for _, b := range a {
		s := strconv.Itoa(int(b))
		key = append(key, byte(len(s)))
		key = append(key, s...)
	}
	return append(key, 0)
}
