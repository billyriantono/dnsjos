// Package install embeds the node installer template and the agent binaries
// (bin/dnsjos-agent-linux-<arch> + .sha256 and bin/dnsjos-agent.version, produced by
// `make agent`). The HTTP handlers live in the nodes package.
package install

import (
	"embed"
	"io/fs"
	"strings"
)

//go:embed all:bin install.sh.tmpl
var assets embed.FS

// Assets exposes install.sh.tmpl and bin/*.
func Assets() fs.FS { return assets }

// AgentVersion is the version the embedded agent binaries were built with (the
// -X main.version of `make agent`), or "" when no agent is embedded.
func AgentVersion() string {
	b, _ := fs.ReadFile(assets, "bin/dnsjos-agent.version")
	return strings.TrimSpace(string(b))
}
