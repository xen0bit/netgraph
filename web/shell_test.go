package web

import (
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
