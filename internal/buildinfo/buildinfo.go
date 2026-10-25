// Package buildinfo holds the version metadata stamped into every netgraph
// binary at link time, by the Makefile and .goreleaser.yaml alike:
//
//	-X github.com/xen0bit/netgraph/internal/buildinfo.Version=...
//
// Keeping it in one package rather than in each main means the sensor, the
// server and the WASM page report a version the same way, from one symbol.
package buildinfo

import (
	"fmt"
	"runtime"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String is the one-line form printed by each binary's `version` subcommand.
func String(binary string) string {
	return fmt.Sprintf("%s %s (commit %s, built %s, %s/%s)",
		binary, Version, Commit, Date, runtime.GOOS, runtime.GOARCH)
}
