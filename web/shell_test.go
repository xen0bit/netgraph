package web

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every module the page loads must be in the service worker's list: one left out
// breaks the installed app the first time the server is away.
func TestServiceWorkerListsEveryModule(t *testing.T) {
	sw, err := os.ReadFile("src/sw.js")
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir("src/js", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel("src", p)
		rel = filepath.ToSlash(rel)
		// The capsule's player is written into capsules, never loaded by the page.
		if rel != "js/capsule-player.js" && !strings.Contains(string(sw), `"`+rel+`"`) {
			t.Errorf("sw.js does not list %s", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The built shell is what the binary embeds and the service worker caches: a
// source file changed without `make web.build` would ship the old UI.
func TestDistMatchesSource(t *testing.T) {
	if _, err := os.Stat("dist"); os.IsNotExist(err) {
		t.Skip("web/dist is not built; run make web.build")
	}
	err := filepath.WalkDir("src", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel("src", p)
		want, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		got, err := os.ReadFile(filepath.Join("dist", rel))
		if err != nil {
			t.Errorf("web/dist is missing %s: run make web.build", filepath.ToSlash(rel))
			return nil
		}
		if !bytes.Equal(want, got) {
			t.Errorf("web/dist/%s differs from web/src/%s: run make web.build", filepath.ToSlash(rel), filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
