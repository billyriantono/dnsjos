package httpx

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	cases := []struct{ remote, xff, want string }{
		{"203.0.113.9:1234", "1.2.3.4", "203.0.113.9"},    // XFF from a non-proxy is ignored
		{"127.0.0.1:1234", "6.6.6.6, 1.2.3.4", "1.2.3.4"}, // rightmost = what our proxy saw
		{"[::1]:1234", "2001:db8::1", "2001:db8::1"},
		{"127.0.0.1:1234", "garbage", "127.0.0.1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		r.Header.Set("X-Forwarded-For", c.xff)
		if got := ClientIP(r); got != c.want {
			t.Errorf("%s + %q: got %s want %s", c.remote, c.xff, got, c.want)
		}
	}
}
