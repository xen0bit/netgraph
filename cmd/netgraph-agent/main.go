// Command netgraph-agent is the optional host agent, for Linux, Windows and
// macOS. It reports local process identity and process-attributed
// connections, and predicts the active policy; on Linux it can enforce deny
// rules through a dedicated nftables table when explicitly enabled. It is
// separate from netgraph-sensor.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xen0bit/netgraph/internal/agent"
	"github.com/xen0bit/netgraph/internal/buildinfo"
)

func main() {
	if err := service(run); err != nil {
		fmt.Fprintln(os.Stderr, "netgraph-agent:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("netgraph-agent", flag.ContinueOnError)
	server := fs.String("server", envOr("NETGRAPH_SERVER", "http://127.0.0.1:8443"), "server URL; $NETGRAPH_SERVER")
	tokenFile := fs.String("token-file", "", "file holding the agent token; $NETGRAPH_AGENT_TOKEN")
	name := fs.String("name", os.Getenv("NETGRAPH_AGENT_NAME"), "agent name; default hostname; $NETGRAPH_AGENT_NAME")
	interval := fs.Duration("interval", defaultInterval, "scan interval")
	once := fs.Bool("once", false, "scan and upload once, then exit")
	refresh := fs.Duration("refresh", time.Minute, "how often an unchanged open connection is sent again")
	enforceMode := fs.String("enforce", "off", "off, or nftables (Linux)")
	apply := fs.Bool("apply", false, "with -enforce=nftables, actually change the host firewall (default dry run)")
	nftTable := fs.String("nft-table", "netgraph_agent", "nftables table for enforcement")
	caFile := fs.String("ca-file", "", "PEM CA bundle to verify the server's certificate")
	cmdlines := fs.Bool("cmdlines", false, "send each process's full command line; off, only the program (arguments can hold secrets)")
	events := fs.String("events", envOr("NETGRAPH_AGENT_EVENTS", "poll"), "poll, or bpf (Linux): name connections as the kernel opens them; needs CAP_BPF, CAP_PERFMON and the host PID namespace; $NETGRAPH_AGENT_EVENTS")
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
	host, _ := os.Hostname()
	client := &agent.Client{Base: strings.TrimRight(*server, "/"), Token: tok, Agent: *name, Boot: bootID()}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("%s: no certificates found", *caFile)
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
		client.HTTP = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	logf := func(format string, a ...any) { fmt.Fprintf(os.Stderr, "netgraph-agent: "+format+"\n", a...) }
	scanner, closeScanner, err := newScanner(*cmdlines, *events, logf)
	if err != nil {
		return err
	}
	defer closeScanner()
	runner := &agent.Runner{Client: client, Scanner: scanner, Interval: *interval, Refresh: *refresh,
		Hello: agent.Hello{Host: host, Version: buildinfo.Version}, Logf: logf}
	switch *enforceMode {
	case "off", "":
	default:
		// Never drop the way back to the server.
		protect, err := serverAddrs(*server)
		if err != nil {
			return err
		}
		e, err := newEnforcer(*enforceMode, *nftTable, !*apply, protect)
		if err != nil {
			return err
		}
		runner.Enforcer = e
	}
	if *once {
		if runner.Enforcer != nil {
			defer runner.Enforcer.Close()
		}
		return runner.Once(ctx)
	}
	return runner.Run(ctx)
}

// serverAddrs resolves the server's host, for the addresses enforcement must
// never drop.
func serverAddrs(server string) ([]netip.Addr, error) {
	u, err := url.Parse(server)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("-server %q is not a URL", server)
	}
	if a, err := netip.ParseAddr(u.Hostname()); err == nil {
		return []netip.Addr{a.Unmap()}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", u.Hostname())
	if err != nil {
		return nil, fmt.Errorf("resolve the server, whose addresses enforcement must not drop: %w", err)
	}
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	return addrs, nil
}

// bootID names this run of the agent: the kernel's boot ID on Linux, else a
// start time.
func bootID() string {
	if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// interrupted is a context that ends on Ctrl-C or SIGTERM.
func interrupted() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
