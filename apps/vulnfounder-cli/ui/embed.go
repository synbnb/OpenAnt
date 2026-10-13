// Package ui provides the embedded web UI templates for the vulnfounder serve command.
package ui

import "embed"

//go:embed dashboard.html index.html repository-manager.html vulnerability-summary.html scan.html artifact-view.html summary.html disclosure.html source-locator.html exposure-surface.html exposure-locator.html device-socket-assets.html device-socket-asset-history.html socket-scope.html settings.html dynamic-test.html dynamic-test-history.html vulnfounder-theme.css vulnfounder-navigation.js vendor/marked.min.js vendor/purify.min.js
var FS embed.FS
