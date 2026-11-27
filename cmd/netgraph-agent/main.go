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
	"sync"
	"syscall"
	"time"

	"github.com/xen0bit/netgraph/internal/agent"
	"github.com/xen0bit/netgraph/internal/agent/enforce"
	"github.com/xen0bit/netgraph/internal/buildinfo"
)

func main() {
	if err := service(run); err != nil {
		fmt.Fprintln(os.Stderr, "netgraph-agent:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	// The other netgraph binaries take `version` as a command; -version and
	// --version are flags below.
	if len(args) > 0 && args[0] == "version" {
		fmt.Println(buildinfo.String("netgraph-agent"))
		return nil
	}
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
		protect, err := resolveServer(ctx, *server, lookupServer)
		if err != nil {
			return err
		}
		set := enforce.NewProtect(protect)
		e, err := newEnforcer(*enforceMode, *nftTable, !*apply, set)
		if err != nil {
			return err
		}
		runner.Enforcer = e
		// The server may move: follow its name, so a deny rule can't cut the
		// agent off from the server that would undo it.
		guard := &serverGuard{server: *server, protect: set, lookup: lookupServer, every: serverResolveEvery, logf: logf}
		go guard.run(ctx)
		runner.OnServerError = func() { guard.refreshAfterError(ctx) }
	}
	if *once {
		if runner.Enforcer != nil {
			defer runner.Enforcer.Close()
		}
		return runner.Once(ctx)
	}
	return runner.Run(ctx)
}

// How often the agent re-resolves the server's host name, and the least time
// between re-resolutions after a failed request: the addresses enforcement
// protects must follow a server that moved, without a server that is down
// turning every failed upload into a DNS lookup.
const (
	serverResolveEvery = 10 * time.Minute
	serverResolveMin   = time.Minute
)

// maxServerAddrs bounds how many addresses a lookup may protect.
const maxServerAddrs = 64

// lookupIP resolves a host name. Tests replace it.
type lookupIP func(ctx context.Context, host string) ([]netip.Addr, error)

func lookupServer(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// resolveServer returns the addresses enforcement must never drop: the
// server's own. A literal address is taken as it is; a name is resolved,
// bounded in time and count, and unmapped and unzoned so it matches what the
// scanner reports.
func resolveServer(ctx context.Context, server string, lookup lookupIP) ([]netip.Addr, error) {
	u, err := url.Parse(server)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("-server %q is not a URL", server)
	}
	if a, err := netip.ParseAddr(u.Hostname()); err == nil {
		return []netip.Addr{a.Unmap().WithZone("")}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addrs, err := lookup(ctx, u.Hostname())
	if err != nil {
		return nil, fmt.Errorf("resolve the server, whose addresses enforcement must not drop: %w", err)
	}
	out := make([]netip.Addr, 0, min(len(addrs), maxServerAddrs))
	seen := make(map[netip.Addr]bool, len(addrs))
	for _, a := range addrs {
		a = a.Unmap().WithZone("")
		if !a.IsValid() || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
		if len(out) >= maxServerAddrs {
			break
		}
	}
	if len(out) == 0 {
		return nil, errors.New("resolve the server, whose addresses enforcement must not drop: no addresses")
	}
	return out, nil
}

// serverGuard keeps the enforcer's protected set on the server's current
// addresses. A name can resolve to a new address while the agent runs, and a
// deny rule for the old one must not cut the agent off from the server that
// would let someone undo it. A failed lookup keeps what is known: a network
// blip must not make the server droppable.
type serverGuard struct {
	server  string
	protect *enforce.Protect
	lookup  lookupIP
	every   time.Duration
	logf    func(string, ...any)

	mu   sync.Mutex
	last time.Time // when a resolution last ran
}

// refresh resolves the server again and replaces the protected set only on
// success. It reports whether it did.
func (g *serverGuard) refresh(ctx context.Context) bool {
	g.mu.Lock()
	g.last = time.Now()
	g.mu.Unlock()
	addrs, err := resolveServer(ctx, g.server, g.lookup)
	if err != nil {
		if g.logf != nil {
			g.logf("%v; keeping %d addresses protected", err, g.protect.Len())
		}
		return false
	}
	g.protect.Replace(addrs)
	return true
}

// refreshAfterError re-resolves after a failed request, at most once a
// minute: a server that is down must not make every failed upload a lookup.
func (g *serverGuard) refreshAfterError(ctx context.Context) {
	g.mu.Lock()
	recent := time.Since(g.last) < serverResolveMin
	g.mu.Unlock()
	if recent {
		return
	}
	g.refresh(ctx)
}

// run re-resolves until ctx ends.
func (g *serverGuard) run(ctx context.Context) {
	every := g.every
	if every <= 0 {
		every = serverResolveEvery
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.refresh(ctx)
		}
	}
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
