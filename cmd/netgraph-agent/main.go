//go:build linux

// Command netgraph-agent is the optional Linux host agent. It reports local
// process identity and process-attributed connections, predicts the active
// policy, and can enforce deny rules through a dedicated nftables table when
// explicitly enabled. It is separate from netgraph-sensor.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xen0bit/netgraph/internal/agent"
	"github.com/xen0bit/netgraph/internal/agent/enforce"
	"github.com/xen0bit/netgraph/internal/agent/linux"
	"github.com/xen0bit/netgraph/internal/buildinfo"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "netgraph-agent:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("netgraph-agent", flag.ContinueOnError)
	server := fs.String("server", envOr("NETGRAPH_SERVER", "http://127.0.0.1:8443"), "server URL; $NETGRAPH_SERVER")
	tokenFile := fs.String("token-file", "", "file holding the agent token; $NETGRAPH_AGENT_TOKEN")
	name := fs.String("name", "", "agent name; default hostname")
	interval := fs.Duration("interval", 10*time.Second, "scan interval")
	once := fs.Bool("once", false, "scan and upload once, then exit")
	enforceMode := fs.String("enforce", "off", "off or nftables")
	apply := fs.Bool("apply", false, "with -enforce=nftables, actually change the host firewall (default dry run)")
	nftTable := fs.String("nft-table", "netgraph_agent", "nftables table for enforcement")
	version := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *version {
		fmt.Println(buildinfo.String("netgraph-agent"))
		return nil
	}
	tok := os.Getenv("NETGRAPH_AGENT_TOKEN")
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		tok = strings.TrimSpace(string(b))
	}
	if tok == "" {
		return errors.New("no agent token: set NETGRAPH_AGENT_TOKEN or -token-file")
	}
	if *name == "" {
		*name, _ = os.Hostname()
	}
	if *name == "" {
		*name = "host-agent"
	}
	client := &agent.Client{Base: strings.TrimRight(*server, "/"), Token: tok, Agent: *name, Boot: bootID()}
	runner := &agent.Runner{Client: client, Scanner: &linux.Scanner{}, Interval: *interval,
		Logf: func(format string, a ...any) { fmt.Fprintf(os.Stderr, "netgraph-agent: "+format+"\n", a...) }}
	switch *enforceMode {
	case "off", "":
	case "nftables":
		runner.Enforcer = &enforce.Nftables{Table: *nftTable, DryRun: !*apply}
	default:
		return fmt.Errorf("-enforce %q is not off or nftables", *enforceMode)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *once {
		if runner.Enforcer != nil {
			defer runner.Enforcer.Close()
		}
		return runner.Once(ctx)
	}
	return runner.Run(ctx)
}

func bootID() string {
	if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
