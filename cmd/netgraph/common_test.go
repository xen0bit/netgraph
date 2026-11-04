package main

import (
	"flag"
	"os"
	"path/filepath"
	"slices"
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

func TestParseInterspersed(t *testing.T) {
	for _, c := range []struct {
		args []string
		at   string
		pos  []string
	}{
		{[]string{"-at", "x", "note"}, "x", []string{"note"}},
		{[]string{"note", "-at", "x"}, "x", []string{"note"}},
		{[]string{"a", "-at", "x", "b"}, "x", []string{"a", "b"}},
		{[]string{"a", "--", "-at", "x"}, "", []string{"a", "-at", "x"}},
		{[]string{"a"}, "", []string{"a"}},
	} {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		at := fs.String("at", "", "")
		if err := parseInterspersed(fs, c.args); err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		if *at != c.at || !slices.Equal(fs.Args(), c.pos) {
			t.Errorf("%v: at=%q args=%q", c.args, *at, fs.Args())
		}
	}
}
