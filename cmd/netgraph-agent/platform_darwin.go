//go:build darwin

package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/xen0bit/netgraph/internal/agent"
	"github.com/xen0bit/netgraph/internal/agent/darwin"
)

// defaultInterval is how often the agent scans: each scan runs lsof and ps.
const defaultInterval = 10 * time.Second

func newScanner(cmdlines bool, events string, _ func(string, ...any)) (agent.Scanner, func(), error) {
	if events != "" && events != "poll" {
		return nil, nil, fmt.Errorf("-events %q: only Linux agents have connection events", events)
	}
	return &darwin.Scanner{Cmdlines: cmdlines}, func() {}, nil
}

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
