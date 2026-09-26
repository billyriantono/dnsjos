// Package migrations embeds the forward-only SQL migrations applied at startup.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
