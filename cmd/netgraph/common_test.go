package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEtcCredential(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "etc_wifi.keys"), []byte("wpa2 home pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if got, want := etcCredential("wifi.keys"), filepath.Join(dir, "etc_wifi.keys"); got != want {
		t.Errorf("present credential = %q, want %q", got, want)
	}
	// A file not in /etc/netgraph has no credential.
	if got := etcCredential("read.token"); got != "" {
		t.Errorf("absent credential = %q, want empty", got)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if got := etcCredential("wifi.keys"); got != "" {
		t.Errorf("outside systemd = %q, want empty", got)
	}
}
