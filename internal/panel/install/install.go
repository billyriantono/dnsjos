// Package install embeds the node installer template and the agent binaries
// (bin/dnsjos-agent-linux-<arch> + .sha256, produced by `make agent`). The HTTP
// handlers live in the nodes package.
package install

import (
	"embed"
	"io/fs"
)

//go:embed all:bin install.sh.tmpl
var assets embed.FS

// Assets exposes install.sh.tmpl and bin/*.
func Assets() fs.FS { return assets }
