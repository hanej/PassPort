// Package docs embeds the documentation files for serving in the admin UI.
package docs

import _ "embed"

//go:embed guide.md
var GuideMarkdown []byte
