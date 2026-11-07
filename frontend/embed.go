// Package frontend embeds the built SPA (Vite output in dist/) so the API
// binary can serve the whole UI as a single executable.
//
// Build order: npm run build (in frontend/) must run before go build,
// otherwise the embed has no files to embed.
package frontend

import "embed"

// FS holds the production frontend build (frontend/dist).
//
//go:embed all:dist
var FS embed.FS
