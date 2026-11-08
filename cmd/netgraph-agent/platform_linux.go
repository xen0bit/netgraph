//go:build linux

package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/xen0bit/netgraph/internal/agent"
	"github.com/xen0bit/netgraph/internal/agent/enforce"
	"github.com/xen0bit/netgraph/internal/agent/linux"
)

// defaultInterval is how often the agent scans. Reading /proc is cheap once
// the scanner knows which process holds each socket, so a short connection
// still has a chance of being seen.
const defaultInterval = 2 * time.Second

func newScanner(cmdlines bool) agent.Scanner {
	return &linux.Scanner{Cmdlines: cmdlines}
}

func newEnforcer(mode, table string, dryRun bool, protect []netip.Addr) (agent.Enforcer, error) {
	if mode != "nftables" {
		return nil, fmt.Errorf("-enforce %q is not off or nftables", mode)
	}
	n, err := enforce.NewNftables(table)
	if err != nil {
		return nil, err
	}
	n.DryRun, n.Protect = dryRun, protect
	return n, nil
}

func service(run func(context.Context, []string) error) error {
	ctx, stop := interrupted()
	defer stop()
	return run(ctx, os.Args[1:])
}
