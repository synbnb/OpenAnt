// Package ui provides the embedded web UI templates for the vulnfounder serve command.
package ui

import "embed"

//go:embed index.html scan.html artifact-view.html summary.html disclosure.html source-locator.html exposure-surface.html exposure-locator.html device-socket-assets.html socket-scope.html dynamic-test.html vulnfounder-theme.css vulnfounder-navigation.js vendor/marked.min.js vendor/purify.min.js
var FS embed.FS
