// Package webbundle embeds the JS generation bundle into the binary so a
// standalone release binary can serve /static/* without SK_WEB_DIR.
//
// web/dist is gitignored and outside any Go package, so the release build
// (release.yml build-binaries, `make web-embed`) copies the Vite output into
// dist/ here before `go build`. A plain checkout only carries dist/.gitkeep:
// `go build ./...` still compiles, FS returns nil and the server falls back
// to the on-disk web directory alone, as before. The Docker image keeps
// serving /app/web (SK_WEB_DIR wins over the embedded copy).
package webbundle

import (
	"embed"
	"io/fs"
)

// BundleName is the file the reveal page loads from /static/.
const BundleName = "sealkeeper-generation.umd.js"

// all: so the dot-file placeholder satisfies the pattern on a checkout
// without a bundle; the static handler refuses dot segments anyway.
//
//go:embed all:dist
var embedded embed.FS

// FS returns the embedded bundle directory, or nil when the binary was
// built without a bundle.
func FS() fs.FS {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		return nil
	}
	return withBundle(sub)
}

// withBundle returns fsys only when it holds a non-empty BundleName.
func withBundle(fsys fs.FS) fs.FS {
	st, err := fs.Stat(fsys, BundleName)
	if err != nil || st.IsDir() || st.Size() == 0 {
		return nil
	}
	return fsys
}
