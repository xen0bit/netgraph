//go:build !linux && !darwin && !windows

package main

import (
	"context"
	"errors"
	"net/netip"

	"github.com/xen0bit/netgraph/internal/agent"
)

var errPlatform = errors.New("netgraph-agent runs on Linux, macOS and Windows")

type noScanner struct{}

func (noScanner) Scan(context.Context) ([]agent.Process, []agent.Connection, error) {
	return nil, nil, errPlatform
}

func newScanner(bool) agent.Scanner { return noScanner{} }

var newEnforcer = func(string, string, bool, []netip.Addr) (agent.Enforcer, error) { return nil, errPlatform }

func service(func(context.Context, []string) error) error { return errPlatform }
