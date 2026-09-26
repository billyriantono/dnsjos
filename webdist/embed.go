// Package webdist embeds the SPA. A plain `go build` embeds the hand-written
// placeholder page; `make panel` copies the Vite build into dist/ (never committed)
// and builds with -tags release so the real UI is embedded instead.
package webdist

import "io/fs"

// FS is the root of the embedded SPA (index.html + assets).
var FS fs.FS
