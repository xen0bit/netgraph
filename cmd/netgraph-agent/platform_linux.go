//go:build linux

package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/xen0bit/netgraph/internal/agent"
	"github.com/xen0bit/netgraph/internal/agent/enforce"
	"github.com/xen0bit/netgraph/internal/agent/linux"
	"github.com/xen0bit/netgraph/internal/agent/linux/bpf"
)

// defaultInterval is how often the agent scans. Reading /proc is cheap once
// the scanner knows which process holds each socket, so a short connection
// still has a chance of being seen.
const defaultInterval = 2 * time.Second

// newScanner reads /proc, and with events "bpf" the kernel's connection
// events too: then a connection lasting milliseconds is named. That needs
// CAP_BPF and CAP_PERFMON, and the host's PID namespace to read the
// processes the kernel names.
func newScanner(cmdlines bool, events string, logf func(string, ...any)) (agent.Scanner, func(), error) {
	s := &linux.Scanner{Cmdlines: cmdlines, Logf: logf}
	switch events {
	case "", "poll":
		return s, func() {}, nil
	case "bpf":
	default:
		return nil, nil, fmt.Errorf("-events %q is not poll or bpf", events)
	}
	// Only this network namespace's sockets: the ones /proc/net shows, and
	// the ones the sensor beside it sees.
	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/net", &st); err != nil {
		return nil, nil, fmt.Errorf("-events=bpf: %w", err)
	}
	r, err := bpf.Open(uint32(st.Ino))
	if err != nil {
		return nil, nil, fmt.Errorf("-events=bpf: %w", err)
	}
	if m := r.Missing(); len(m) > 0 {
		logf("-events=bpf: this kernel can't report %s; /proc polling still covers them", strings.Join(m, ", "))
	}
	s.Listen(r)
	return s, func() { r.Close() }, nil
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
