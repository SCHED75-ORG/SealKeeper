package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sched75/sealkeeper/internal/webbundle"
)

// A standalone binary started from a cwd that merely has a web/ directory
// (a repo checkout, /srv, a home dir) must not pick it as WebDir: it would
// hide the embedded bundle and 404 /static/sealkeeper-generation.umd.js.
// Only a candidate holding the bundle file is autodetected.
func TestAutodetectWebDirRequiresBundle(t *testing.T) {
	bundle := webbundle.BundleName
	cases := []struct {
		name  string
		dirs  []string
		files map[string]string
		want  string
	}{
		{name: "nothing", want: ""},
		{name: "empty web dir", dirs: []string{"web"}, want: ""},
		{name: "source-only web dir", dirs: []string{"web/dist"}, files: map[string]string{"web/src/index.js": "x"}, want: ""},
		{name: "empty bundle file", files: map[string]string{"web/" + bundle: ""}, want: ""},
		{name: "bundle is a directory", dirs: []string{"web/" + bundle}, want: ""},
		{name: "bundle in web", files: map[string]string{"web/" + bundle: "x"}, want: "web"},
		{name: "bundle in web/dist first", files: map[string]string{"web/dist/" + bundle: "x", "web/" + bundle: "x"}, want: "web/dist"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, d := range c.dirs {
				if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(d)), 0o750); err != nil {
					t.Fatal(err)
				}
			}
			for p, content := range c.files {
				full := filepath.Join(dir, filepath.FromSlash(p))
				if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			t.Chdir(dir)
			if got := autodetectWebDir(); got != c.want {
				t.Errorf("autodetectWebDir() = %q, want %q", got, c.want)
			}
		})
	}
}
