package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

func TestAdoptOOTB(t *testing.T) {
	ref, err := os.ReadFile("testdata/dnsdist-ootb.yml")
	if err != nil {
		t.Fatal(err)
	}
	y := string(ref)
	for _, r := range [][2]string{
		{"key: <redacted>\n  dot", "key: /etc/dnsdist/tls/key.pem\n  dot"},
		{"key: <redacted>\n\nrules", "key: /etc/dnsdist/tls/key.pem\n\nrules"},
		{"apikey: <redacted>", `apikey: "api#key"`},
		{"password: <redacted>", "password: 'it''s-secret' # comment"},
		{"    key: <redacted>", "    key: Y29uc29sZS1rZXk="},
	} {
		if !strings.Contains(y, r[0]) {
			t.Fatalf("reference file changed: %q not found", r[0])
		}
		y = strings.Replace(y, r[0], r[1], 1)
	}
	p := filepath.Join(t.TempDir(), "dnsdist.yml")
	os.WriteFile(p, []byte(y), 0o600)

	a, err := adoptOOTB(p)
	if err != nil {
		t.Fatal(err)
	}
	if a.Secrets != (Secrets{ConsoleKey: "Y29uc29sZS1rZXk=", WebPassword: "it's-secret", WebAPIKey: "api#key"}) {
		t.Fatalf("secrets: %+v", a.Secrets)
	}
	patch, _ := json.Marshal(a.Overrides)
	want := `{"listen":{"do53":{"addresses":["0.0.0.0:53","[::]:53"]},` +
		`"doh":{"addresses":["0.0.0.0:443","[::]:443"],"enabled":true},"dot":{"addresses":["0.0.0.0:853","[::]:853"],"enabled":true},` +
		`"tls":{"cert_file":"/etc/dnsdist/tls/cert.pem","key_file":"/etc/dnsdist/tls/key.pem"}},` +
		`"webserver":{"listen":"0.0.0.0:8083","prometheus_acl":["127.0.0.1/8","198.51.100.16/29","198.51.100.8/29","198.51.100.24/29","198.51.100.32/29"]}}`
	if string(patch) != want {
		t.Fatalf("overrides:\n got %s\nwant %s", patch, want)
	}
	spec, err := api.MergeSpec(api.DefaultConfigSpec(), patch)
	if err != nil {
		t.Fatal(err)
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("merged spec invalid: %v", err)
	}
}
