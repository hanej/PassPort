package web

import "embed"

//go:embed templates static
var Assets embed.FS
