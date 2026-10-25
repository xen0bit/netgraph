// Command netgraph-sensor runs on the router. It captures LAN traffic, decodes
// it into events (flows, DNS, DHCP, mDNS, ARP/NDP, TLS SNI, ...) and ships them
// to a netgraph server. It keeps no database: everything it learns leaves the
// box, so it fits a 512 MB router and cross-compiles to every Linux arch,
// mips included.
//
//	netgraph-sensor run -iface br-lan -server https://host:8443 -token-file F
//	netgraph-sensor run -pcap capture.pcap -server ...
//	netgraph-sensor version
//
// Capturing needs CAP_NET_RAW: run as root, or `setcap cap_net_raw+ep`.
//
// This binary must never link SQLite or d2 — they do not build for mips, and
// the size budget is a few MB. deps_test.go enforces it.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xen0bit/netgraph/internal/buildinfo"
	"github.com/xen0bit/netgraph/internal/capture"
	"github.com/xen0bit/netgraph/internal/flow"
	"github.com/xen0bit/netgraph/internal/sensor"
	"github.com/xen0bit/netgraph/internal/wire"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version", "-version", "--version":
		fmt.Println(buildinfo.String("netgraph-sensor"))
	case "help", "-h", "-help", "--help":
		usage()
	case "run":
		if err := run(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "netgraph-sensor:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "netgraph-sensor: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: netgraph-sensor <command> [flags]

commands:
  run        capture and ship events to a netgraph server
  version    print version information

Run 'netgraph-sensor run -h' for run's flags.
`)
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	ifaces := fs.String("iface", envOr("NETGRAPH_IFACE", ""), "comma-separated interfaces to capture (e.g. br-lan); $NETGRAPH_IFACE")
	pcap := fs.String("pcap", "", "replay a pcap/pcapng file instead of capturing live")
	server := fs.String("server", envOr("NETGRAPH_SERVER", ""), "netgraph server URL, or - for JSON lines on stdout; $NETGRAPH_SERVER")
	tokenFile := fs.String("token-file", "", "file holding the ingest token (default $NETGRAPH_TOKEN)")
	name := fs.String("name", envOr("NETGRAPH_SENSOR_NAME", hostname()), "sensor name reported to the server")
	caFile := fs.String("ca-file", "", "PEM CA bundle to verify the server's certificate")
	insecure := fs.Bool("insecure-skip-verify", false, "do not verify the server's TLS certificate")
	promisc := fs.Bool("promisc", false, "put interfaces in promiscuous mode (SPAN/mirror ports)")
	ringMB := fs.Int("ring-mb", 8, "AF_PACKET ring size per interface, MiB")
	active := fs.Duration("active-timeout", 30*time.Second, "export an interval record for long flows this often")
	tcpIdle := fs.Duration("tcp-idle", 5*time.Minute, "expire silent TCP flows after this")
	udpIdle := fs.Duration("udp-idle", 60*time.Second, "expire silent UDP/ICMP flows after this")
	maxFlows := fs.Int("max-flows", 65536, "flow table capacity; least recently used flows are evicted beyond it")
	spoolMB := fs.Int("spool-mb", 32, "memory for batches awaiting delivery, MiB; oldest are dropped beyond it")
	flushEvery := fs.Duration("flush", 2*time.Second, "send batches at least this often")
	memLimit := fs.Int("mem-limit-mb", 128, "Go soft memory limit, MiB, unless $GOMEMLIMIT is set (0: none)")
	logLevel := fs.String("log-level", "info", "debug, info, warn or error")
	logFormat := fs.String("log-format", "text", "text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := newLogger(*logLevel, *logFormat)
	slog.SetDefault(log)
	if *memLimit > 0 && os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(int64(*memLimit) << 20)
	}
	if (*ifaces == "") == (*pcap == "") {
		return errors.New("exactly one of -iface or -pcap is required")
	}
	if *server == "" {
		return errors.New("-server is required (use - for stdout)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var out wire.Emitter
	var shipper *wire.Shipper
	var ignore func(src, dst netip.AddrPort) bool
	if *server == "-" {
		out = wire.NewJSONWriter(os.Stdout)
	} else {
		token, err := readToken(*tokenFile)
		if err != nil {
			return err
		}
		tlsCfg, err := tlsConfig(*caFile, *insecure)
		if err != nil {
			return err
		}
		base := strings.TrimRight(*server, "/")
		shipper = wire.NewShipper(wire.ShipperConfig{
			URL: base, Token: token, Sensor: *name, TLSConfig: tlsCfg,
			FlushInterval: *flushEvery, SpoolBytes: *spoolMB << 20, Logger: log,
		})
		out = shipper
		self, err := newSelfFilter(ctx, base)
		if err != nil {
			return err
		}
		ignore = self.match
	}

	proc := sensor.NewProcessor(sensor.Config{
		Flow:   flow.Config{ActiveTimeout: *active, TCPIdle: *tcpIdle, UDPIdle: *udpIdle, MaxFlows: *maxFlows},
		Logger: log, Ignore: ignore,
	}, out)
	var names []string
	if *ifaces != "" {
		names = strings.Split(*ifaces, ",")
	}
	r := &sensor.Runner{
		Processor: proc, Out: out,
		Hello: wire.Hello{
			Name: *name, Version: buildinfo.Version, OS: runtime.GOOS, Arch: runtime.GOARCH,
			Interfaces: sensor.InterfaceInfo(names), ActiveTimeout: *active,
		},
	}

	var shipDone chan struct{}
	shipCtx, cancelShip := context.WithCancel(context.Background())
	defer cancelShip()
	if shipper != nil {
		r.ShipperStats = shipper.Stats
		shipDone = make(chan struct{})
		go func() { defer close(shipDone); shipper.Run(shipCtx) }()
		log.Info("shipping to server", "server", *server, "sensor", *name, "boot", shipper.Boot())
	}

	var err error
	if *pcap != "" {
		src, oerr := capture.OpenFile(*pcap)
		if oerr != nil {
			return oerr
		}
		log.Info("replaying capture", "file", *pcap)
		err = r.RunFile(ctx, src)
	} else {
		var sources []capture.Source
		for _, n := range names {
			src, oerr := capture.OpenLive(capture.LiveConfig{Interface: strings.TrimSpace(n), RingBytes: *ringMB << 20, Promiscuous: *promisc})
			if oerr != nil {
				for _, s := range sources {
					s.Close()
				}
				return oerr
			}
			sources = append(sources, src)
			log.Info("capturing", "iface", n)
		}
		err = r.RunLive(ctx, sources)
	}
	if shipper != nil {
		// Run drains the spool (bounded) when its context ends.
		cancelShip()
		<-shipDone
	}
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
		h = "sensor"
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

func newLogger(level, format string) *slog.Logger {
	var l slog.Level
	_ = l.UnmarshalText([]byte(level))
	opts := &slog.HandlerOptions{Level: l}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

// selfFilter recognises the sensor's own connection to the server, so
// shipping events does not itself become events. The server's name is
// re-resolved periodically in case it moves.
type selfFilter struct {
	host string
	port uint16
	mu   sync.RWMutex
	ips  map[netip.Addr]bool
}

func newSelfFilter(ctx context.Context, base string) (*selfFilter, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid -server URL %q", base)
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port in -server URL %q", base)
	}
	f := &selfFilter{host: u.Hostname(), port: uint16(p), ips: map[netip.Addr]bool{}}
	f.resolve()
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				f.resolve()
			}
		}
	}()
	return f, nil
}

func (f *selfFilter) resolve() {
	ips := map[netip.Addr]bool{}
	if a, err := netip.ParseAddr(f.host); err == nil {
		ips[a.Unmap()] = true
	} else if addrs, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", f.host); err == nil {
		for _, a := range addrs {
			ips[a.Unmap()] = true
		}
	}
	f.mu.Lock()
	f.ips = ips
	f.mu.Unlock()
}

func (f *selfFilter) match(src, dst netip.AddrPort) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return dst.Port() == f.port && f.ips[dst.Addr()] || src.Port() == f.port && f.ips[src.Addr()]
}
