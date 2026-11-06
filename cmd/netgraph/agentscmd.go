package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/xen0bit/netgraph/internal/model"
)

type agentsBackend interface {
	Agents(context.Context) ([]model.Agent, error)
	AgentProcesses(context.Context, string, int) ([]model.AgentProcess, error)
	AgentConnections(context.Context, string, int) ([]model.AgentConnection, error)
}

func runAgents(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: netgraph agents list|processes|connections")
	}
	switch args[0] {
	case "list":
		return runAgentsList(args[1:])
	case "processes":
		return runAgentProcesses(args[1:])
	case "connections":
		return runAgentConnections(args[1:])
	}
	return fmt.Errorf("agents: %q is not a command", args[0])
}

func openAgentsBackend(b *backendFlags) (agentsBackend, func(), error) {
	be, closeFn, err := b.open()
	if err != nil {
		return nil, nil, err
	}
	ab, ok := be.(agentsBackend)
	if !ok {
		closeFn()
		return nil, nil, errors.New("this backend can't do agents")
	}
	return ab, closeFn, nil
}

func runAgentsList(args []string) error {
	fs := flag.NewFlagSet("agents list", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	be, closeFn, err := openAgentsBackend(&b)
	if err != nil {
		return err
	}
	defer closeFn()
	out, err := be.Agents(context.Background())
	if err != nil {
		return err
	}
	return encode(out)
}

func runAgentProcesses(args []string) error {
	fs := flag.NewFlagSet("agents processes", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	name := fs.String("agent", "", "agent name")
	limit := fs.Int("limit", 500, "maximum rows")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *name == "" && len(fs.Args()) > 0 {
		*name = fs.Arg(0)
	}
	be, closeFn, err := openAgentsBackend(&b)
	if err != nil {
		return err
	}
	defer closeFn()
	out, err := be.AgentProcesses(context.Background(), *name, *limit)
	if err != nil {
		return err
	}
	return encode(out)
}

func runAgentConnections(args []string) error {
	fs := flag.NewFlagSet("agents connections", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	name := fs.String("agent", "", "agent name")
	limit := fs.Int("limit", 500, "maximum rows")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *name == "" && len(fs.Args()) > 0 {
		*name = fs.Arg(0)
	}
	be, closeFn, err := openAgentsBackend(&b)
	if err != nil {
		return err
	}
	defer closeFn()
	out, err := be.AgentConnections(context.Background(), *name, *limit)
	if err != nil {
		return err
	}
	return encode(out)
}
