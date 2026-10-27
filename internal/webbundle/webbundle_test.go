package webbundle

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

func TestEmbedPatternCompilesWithPlaceholder(t *testing.T) {
	t.Parallel()
	if _, err := fs.Stat(embedded, "dist/.gitkeep"); err != nil {
		t.Fatalf("placeholder missing from the embedded tree: %v", err)
	}
}

func TestWithBundle(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		fsys fstest.MapFS
		want bool
	}{
		{"placeholder only", fstest.MapFS{".gitkeep": {}}, false},
		{"empty bundle", fstest.MapFS{BundleName: {}}, false},
		{"bundle is a dir", fstest.MapFS{BundleName + "/x": {Data: []byte("x")}}, false},
		{"bundle", fstest.MapFS{BundleName: {Data: []byte("window.SealKeeper={}")}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := withBundle(c.fsys) != nil; got != c.want {
				t.Errorf("withBundle = %v, want %v", got, c.want)
			}
		})
	}
}

// FS must agree with what was embedded: nil on a checkout without a copied
// bundle, the bundle itself after `make web-embed` / the release build.
func TestFSMatchesEmbeddedTree(t *testing.T) {
	t.Parallel()
	_, statErr := fs.Stat(embedded, "dist/"+BundleName)
	got := FS()
	if (statErr == nil) != (got != nil) {
		t.Fatalf("FS() = %v with embedded bundle stat err %v", got, statErr)
	}
	if got != nil {
		if b, err := fs.ReadFile(got, BundleName); err != nil || len(b) == 0 {
			t.Fatalf("embedded bundle unreadable: %v (%d bytes)", err, len(b))
		}
	}
}
