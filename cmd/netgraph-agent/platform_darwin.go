//go:build darwin

package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"

	"github.com/xen0bit/netgraph/internal/agent"
	"github.com/xen0bit/netgraph/internal/agent/darwin"
)

func newScanner(cmdlines bool) agent.Scanner { return &darwin.Scanner{Cmdlines: cmdlines} }

// macOS reports and predicts only: enforcing would need pf or a Network
// Extension, and netgraph changes no firewall it doesn't own.
// A variable, so main's error check isn't "always true" to staticcheck here.
var newEnforcer = func(mode, _ string, _ bool, _ []netip.Addr) (agent.Enforcer, error) {
	return nil, fmt.Errorf("-enforce %q: macOS agents observe only; use -enforce=off", mode)
}

func service(run func(context.Context, []string) error) error {
	ctx, stop := interrupted()
	defer stop()
	return run(ctx, os.Args[1:])
}
