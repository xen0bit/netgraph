// Command netgraph-edge runs VPN listeners whose traffic reports itself to a
// netgraph server: who connected, from where, holding which address, and
// every flow they made through the tunnel.
//
//	netgraph-edge run -server https://netgraph:8443 -token-file /etc/netgraph-edge/token \
//	    -listeners /etc/netgraph-edge/listeners
//
// Each JSON file in -listeners is one listener: a protocol and its options,
// exactly as `veepin serve <protocol>` takes them (see vpn/doc/usage). SIGHUP
// re-reads the directory; a changed file restarts only its own listener.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xen0bit/netgraph/internal/buildinfo"
	"github.com/xen0bit/netgraph/internal/edge"
	"github.com/xen0bit/netgraph/internal/flow"
	"github.com/xen0bit/netgraph/internal/wire"

	// Every production protocol, and each one's post-quantum variant. TOY is
	// left out on purpose: it is an insecure teaching example and must never
	// carry anyone's traffic.
	_ "github.com/xen0bit/netgraph/vpn/amneziawg"
	_ "github.com/xen0bit/netgraph/vpn/anyconnect"
	_ "github.com/xen0bit/netgraph/vpn/anyconnect/pq"
	_ "github.com/xen0bit/netgraph/vpn/cisco"
	_ "github.com/xen0bit/netgraph/vpn/fortinet"
	_ "github.com/xen0bit/netgraph/vpn/fortinet/pq"
	_ "github.com/xen0bit/netgraph/vpn/gp"
	_ "github.com/xen0bit/netgraph/vpn/gp/pq"
	_ "github.com/xen0bit/netgraph/vpn/ikev2"
	_ "github.com/xen0bit/netgraph/vpn/ikev2/pq"
	_ "github.com/xen0bit/netgraph/vpn/l2tp"
	_ "github.com/xen0bit/netgraph/vpn/l2tpv3"
	_ "github.com/xen0bit/netgraph/vpn/masque"
	_ "github.com/xen0bit/netgraph/vpn/masque/pq"
	_ "github.com/xen0bit/netgraph/vpn/nebula"
	_ "github.com/xen0bit/netgraph/vpn/openvpn"
	_ "github.com/xen0bit/netgraph/vpn/openvpn/pq"
	_ "github.com/xen0bit/netgraph/vpn/pulse"
	_ "github.com/xen0bit/netgraph/vpn/pulse/pq"
	_ "github.com/xen0bit/netgraph/vpn/softether"
	_ "github.com/xen0bit/netgraph/vpn/softether/pq"
	_ "github.com/xen0bit/netgraph/vpn/ssh"
	_ "github.com/xen0bit/netgraph/vpn/ssh/pq"
	_ "github.com/xen0bit/netgraph/vpn/sstp"
	_ "github.com/xen0bit/netgraph/vpn/sstp/pq"
	_ "github.com/xen0bit/netgraph/vpn/wireguard"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		if err := run(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "netgraph-edge:", err)
			os.Exit(1)
		}
	case "version", "-version", "--version":
		fmt.Println("netgraph-edge", buildinfo.Version)
	case "-h", "-help", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "netgraph-edge: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: netgraph-edge <command> [flags]

commands:
  run        run the VPN listeners and report to a netgraph server
  version    print version information

Run 'netgraph-edge run -h' for run's flags.
`)
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	server := fs.String("server", envOr("NETGRAPH_SERVER", ""), "netgraph server URL, or - for JSON lines on stdout; $NETGRAPH_SERVER")
	tokenFile := fs.String("token-file", "", "file holding the ingest token (default $NETGRAPH_TOKEN)")
	name := fs.String("name", envOr("NETGRAPH_EDGE_NAME", hostname()), "edge name reported to the server")
	listeners := fs.String("listeners", envOr("NETGRAPH_EDGE_LISTENERS", "/etc/netgraph-edge/listeners"), "directory of listener JSON files; $NETGRAPH_EDGE_LISTENERS")
	caFile := fs.String("ca-file", "", "PEM CA bundle to verify the server's certificate")
	insecure := fs.Bool("insecure-skip-verify", false, "do not verify the server's TLS certificate")
	ringMB := fs.Int("ring-mb", 8, "AF_PACKET ring size per listener's TUN, MiB")
	active := fs.Duration("active-timeout", 30*time.Second, "export an interval record for long flows this often")
	tcpIdle := fs.Duration("tcp-idle", 5*time.Minute, "expire silent TCP flows after this")
	udpIdle := fs.Duration("udp-idle", 60*time.Second, "expire silent UDP/ICMP flows after this")
	maxFlows := fs.Int("max-flows", 65536, "flow table capacity; least recently used flows are evicted beyond it")
	spoolMB := fs.Int("spool-mb", 32, "memory for batches awaiting delivery, MiB; oldest are dropped beyond it")
	flushEvery := fs.Duration("flush", 2*time.Second, "send batches at least this often")
	logLevel := fs.String("log-level", "info", "debug, info, warn or error")
	logFormat := fs.String("log-format", "text", "text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var level slog.LevelVar
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		return fmt.Errorf("-log-level: %w", err)
	}
	opts := &slog.HandlerOptions{Level: &level}
	log := slog.New(slog.NewTextHandler(os.Stderr, opts))
	if *logFormat == "json" {
		log = slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	slog.SetDefault(log)
	if *server == "" {
		return errors.New("-server is required (use - for stdout)")
	}
	for _, d := range []struct {
		name string
		v    time.Duration
	}{{"-active-timeout", *active}, {"-tcp-idle", *tcpIdle}, {"-udp-idle", *udpIdle}, {"-flush", *flushEvery}} {
		if d.v <= 0 {
			return fmt.Errorf("%s must be positive", d.name)
		}
	}
	for _, n := range []struct {
		name string
		v    int
	}{{"-ring-mb", *ringMB}, {"-max-flows", *maxFlows}, {"-spool-mb", *spoolMB}} {
		if n.v <= 0 {
			return fmt.Errorf("%s must be positive", n.name)
		}
	}
	if st, err := os.Stat(*listeners); err != nil || !st.IsDir() {
		return fmt.Errorf("-listeners %s: not a directory", *listeners)
	}

	var out wire.Emitter
	var shipper *wire.Shipper
	if *server == "-" {
		out = wire.NewJSONWriter(os.Stdout)
	} else {
		token, err := readToken(*tokenFile)
		if err != nil {
			return err
		}
		if token == "" {
			log.Warn("no ingest token set: if the server requires one, every batch will be refused. Set NETGRAPH_TOKEN or -token-file")
		}
		tlsCfg, err := tlsConfig(*caFile, *insecure)
		if err != nil {
			return err
		}
		shipper = wire.NewShipper(wire.ShipperConfig{
			URL: strings.TrimRight(*server, "/"), Token: token, Sensor: *name, TLSConfig: tlsCfg,
			FlushInterval: *flushEvery, SpoolBytes: *spoolMB << 20, Logger: log,
		})
		out = shipper
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	shipCtx, stopShipping := context.WithCancel(context.Background())
	shipped := make(chan struct{})
	if shipper != nil {
		go func() { defer close(shipped); shipper.Run(shipCtx) }()
	} else {
		close(shipped)
	}

	e := edge.New(edge.Config{
		Name: *name, ListenerDir: *listeners, Out: out, Logger: log, RingBytes: *ringMB << 20,
		Flow: flow.Config{ActiveTimeout: *active, TCPIdle: *tcpIdle, UDPIdle: *udpIdle, MaxFlows: *maxFlows},
	})
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			log.Info("SIGHUP: re-reading listeners", "dir", *listeners)
			if err := e.Reload(); err != nil {
				log.Warn("reload", "err", err)
			}
		}
	}()
	log.Info("netgraph-edge starting", "name", *name, "listeners", *listeners, "version", buildinfo.Version)
	err := e.Run(ctx)

	// The sessions closed and flows flushed by Run are still queued: the
	// shipper drains its spool (bounded) when its context ends.
	stopShipping()
	<-shipped
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	return err
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		h = "edge"
	}
	return h
}

func readToken(file string) (string, error) {
	if file == "" {
		return os.Getenv("NETGRAPH_TOKEN"), nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("token file: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

func tlsConfig(caFile string, insecure bool) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure} //nolint:gosec // opt-in flag
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no certificates found", caFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}
