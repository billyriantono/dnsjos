//go:build !release

package webdist

import (
	"embed"
	"io/fs"
)

//go:embed placeholder
var placeholder embed.FS

func init() { FS, _ = fs.Sub(placeholder, "placeholder") }
