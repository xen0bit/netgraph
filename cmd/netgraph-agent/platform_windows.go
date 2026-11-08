//go:build windows

package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/xen0bit/netgraph/internal/agent"
	"github.com/xen0bit/netgraph/internal/agent/windows"
)

// defaultInterval is how often the agent scans.
const defaultInterval = 10 * time.Second

func newScanner(cmdlines bool) agent.Scanner { return &windows.Scanner{Cmdlines: cmdlines} }

// Windows reports and predicts only: enforcing would need the Windows
// Filtering Platform, and netgraph changes no firewall it doesn't own.
// A variable, so main's error check isn't "always true" to staticcheck here.
var newEnforcer = func(mode, _ string, _ bool, _ []netip.Addr) (agent.Enforcer, error) {
	return nil, fmt.Errorf("-enforce %q: Windows agents observe only; use -enforce=off", mode)
}

// service runs the agent under the Service Control Manager when it started
// it (sc.exe create ... binPath= "netgraph-agent.exe -token-file ..."), and
// as a console program otherwise.
func service(run func(context.Context, []string) error) error {
	is, err := svc.IsWindowsService()
	if err != nil || !is {
		ctx, stop := interrupted()
		defer stop()
		return run(ctx, os.Args[1:])
	}
	return svc.Run("netgraph-agent", &handler{run: run})
}

type handler struct {
	run func(context.Context, []string) error
}

func (h *handler) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	// The service's own arguments (sc.exe start netgraph-agent ...) follow
	// the ones in its binPath.
	go func() { done <- h.run(ctx, append(os.Args[1:], args[min(len(args), 1):]...)) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "netgraph-agent:", err)
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
			}
		}
	}
}
