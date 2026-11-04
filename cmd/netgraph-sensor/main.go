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
	"encoding/hex"
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
	"github.com/xen0bit/netgraph/internal/conntrack"
	"github.com/xen0bit/netgraph/internal/flow"
	"github.com/xen0bit/netgraph/internal/rdns"
	"github.com/xen0bit/netgraph/internal/sensor"
	"github.com/xen0bit/netgraph/internal/wifi"
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
	case "check":
		if err := check(os.Args[2:]); err != nil {
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
  check      diagnose an interface, permissions and server connection
  version    print version information

Run 'netgraph-sensor run -h' for run's flags.
`)
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	ifaces := fs.String("iface", envOr("NETGRAPH_IFACE", ""), "comma-separated interfaces to capture: names (br-lan), or an address or CIDR the interface holds; $NETGRAPH_IFACE")
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
	rdnsOn := fs.Bool("rdns", true, "resolve reverse DNS names for local hosts as they are observed (live capture only)")
	rdnsTimeout := fs.Duration("rdns-timeout", 2*time.Second, "bound on one reverse DNS lookup")
	rdnsWorkers := fs.Int("rdns-workers", 4, "concurrent reverse DNS lookups")
	rdnsTTL := fs.Duration("rdns-ttl", time.Hour, "reuse a reverse DNS answer for this long")
	wifiHop := fs.Bool("wifi-hop", false, "hop channels on monitor-mode interfaces")
	wifiDwell := fs.Duration("wifi-dwell", 250*time.Millisecond, "time to stay on each channel while hopping")
	wifiChannels := fs.String("wifi-channels", "", "comma-separated channels to hop (default: common 2.4/5 GHz channels)")
	wifiFreqs := fs.String("wifi-frequencies", "", "comma-separated frequencies in MHz to hop instead of channels (for 6 GHz, e.g. 5955,5975)")
	wifi6 := fs.Bool("wifi-6ghz", false, "also hop the 20 MHz 6 GHz plan (needs a 6 GHz-capable monitor interface)")
	wifiData := fs.Bool("wifi-data", false, "emit one event per Wi-Fi data frame (noisy; management and handshakes are always reported)")
	conntrackFlag := fs.String("conntrack", "off", "also read the kernel's connection table: offloaded reports what hardware offload hides from capture; all reports everything, with -capture=false (needs CAP_NET_ADMIN)")
	conntrackEvery := fs.Duration("conntrack-every", 10*time.Second, "how often to read the connection table")
	remoteConfig := fs.Bool("remote-config", true, "take settings the server offers, held in memory only: log level, reverse DNS, active timeout and flush interval")
	captureOn := fs.Bool("capture", true, "capture packets on -iface; with false, -iface only says which networks are local, and -conntrack supplies the traffic")
	memLimit := fs.Int("mem-limit-mb", 128, "Go soft memory limit, MiB, unless $GOMEMLIMIT is set (0: none)")
	logLevel := fs.String("log-level", "info", "debug, info, warn or error")
	logFormat := fs.String("log-format", "text", "text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var level slog.LevelVar
	_ = level.UnmarshalText([]byte(*logLevel))
	log := newLevelLogger(&level, *logFormat)
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
	ctMode, ok := conntrack.ParseMode(*conntrackFlag)
	if !ok {
		return fmt.Errorf("-conntrack: %q is not off, offloaded or all", *conntrackFlag)
	}
	if *pcap != "" && ctMode != conntrack.Off {
		return errors.New("-conntrack reads this machine's table now, which has nothing to do with a replay")
	}
	if !*captureOn && ctMode == conntrack.Off {
		return errors.New("-capture=false needs -conntrack: there would be nothing to report")
	}
	if *captureOn && ctMode == conntrack.All {
		return errors.New("-conntrack all with capture would count everything twice: use -conntrack offloaded, or add -capture=false")
	}
	for _, d := range []struct {
		name string
		v    time.Duration
	}{{"-active-timeout", *active}, {"-tcp-idle", *tcpIdle}, {"-udp-idle", *udpIdle}, {"-flush", *flushEvery},
		{"-rdns-timeout", *rdnsTimeout}, {"-rdns-ttl", *rdnsTTL}, {"-wifi-dwell", *wifiDwell}, {"-conntrack-every", *conntrackEvery}} {
		if d.v <= 0 {
			return fmt.Errorf("%s must be positive", d.name)
		}
	}
	for _, n := range []struct {
		name string
		v    int
	}{{"-ring-mb", *ringMB}, {"-max-flows", *maxFlows}, {"-spool-mb", *spoolMB}, {"-rdns-workers", *rdnsWorkers}} {
		if n.v <= 0 {
			return fmt.Errorf("%s must be positive", n.name)
		}
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
		self, err := newSelfFilter(ctx, base)
		if err != nil {
			return err
		}
		shipper = wire.NewShipper(wire.ShipperConfig{
			URL: base, Token: token, Sensor: *name, TLSConfig: tlsCfg,
			FlushInterval: *flushEvery, SpoolBytes: *spoolMB << 20, Logger: log,
			OnDial: self.observe,
		})
		out = shipper
		ignore = self.match
	}

	var names []string
	if *ifaces != "" {
		for _, v := range strings.Split(*ifaces, ",") {
			n, err := sensor.ResolveInterface(v)
			if err != nil {
				return err
			}
			names = append(names, n)
		}
	}
	liveNames := append([]string(nil), names...)
	var namesMu sync.Mutex
	settings := newSettings(*logLevel, *rdnsOn && *pcap == "", *active, *flushEvery, &level)
	buildHello := func() wire.Hello {
		namesMu.Lock()
		defer namesMu.Unlock()
		h := wire.Hello{
			Name: *name, Version: buildinfo.Version, OS: runtime.GOOS, Arch: runtime.GOARCH,
			Interfaces: sensor.InterfaceInfo(liveNames), ActiveTimeout: settings.activeTimeout(),
		}
		if *remoteConfig && shipperWanted(*server) {
			c := settings.inEffect()
			h.Config = &c
		}
		return h
	}
	hello := buildHello()

	// Wi-Fi keys come from the server (below) and live only in memory.
	// Without them, management frames and handshakes are still decoded and
	// open networks still feed the IP pipeline.
	wifiProc := wifi.NewProcessor(wifi.Config{
		Keys: wifi.NewKeyring(), Logger: log, IncludeData: *wifiData,
		Emit: func(ev wire.Event) { out.Emit(ev) },
	})

	// Reverse DNS is an active lookup, so it is only done on live capture:
	// a replay must not depend on the resolver of the machine replaying it.
	var reverse *rdns.Lookup
	if *pcap == "" {
		reverse = rdns.New(rdns.Config{
			Timeout: *rdnsTimeout, Workers: *rdnsWorkers, TTL: *rdnsTTL, Logger: log,
			Emit: func(n rdns.Name) {
				out.Emit(wire.Event{Type: wire.TypeName, TS: n.TS, Name: &wire.Name{
					MAC: n.MAC, IP: n.IP, Name: n.Name, Proto: "rdns",
				}})
			},
		})
		defer reverse.Close()
		reverse.SetEnabled(*rdnsOn)
	}
	proc := sensor.NewProcessor(sensor.Config{
		Flow:   flow.Config{ActiveTimeout: *active, TCPIdle: *tcpIdle, UDPIdle: *udpIdle, MaxFlows: *maxFlows},
		Logger: log, Ignore: ignore,
		RDNS: reverse, IsLocal: sensor.LocalChecker(hello.Interfaces), WiFi: wifiProc,
	}, out)
	r := &sensor.Runner{Processor: proc, Out: out, Hello: hello, HelloFunc: buildHello}
	settings.apply = func(c wire.SensorConfig) {
		if d := time.Duration(c.ActiveTimeoutS) * time.Second; d > 0 {
			proc.SetActiveTimeout(d)
		}
		if reverse != nil && c.RDNS != nil {
			reverse.SetEnabled(*c.RDNS)
		}
		if shipper != nil {
			shipper.SetFlushInterval(time.Duration(c.FlushS) * time.Second)
		}
	}

	var shipDone chan struct{}
	shipCtx, cancelShip := context.WithCancel(context.Background())
	defer cancelShip()
	if shipper != nil {
		r.ShipperStats = shipper.Stats
		shipDone = make(chan struct{})
		go func() { defer close(shipDone); shipper.Run(shipCtx) }()
		log.Info("shipping to server", "server", *server, "sensor", *name, "boot", shipper.Boot())
		// Wi-Fi keys are configured on the server: fetch its PMKs, WEP
		// keys and stored handshake nonces, and keep them current. They
		// are held in memory only; the sensor writes nothing to disk and
		// sends no key back. The first load is synchronous (bounded) so
		// keys are in place before capture begins, but a down server
		// never delays startup past the timeout.
		loadCtx, cancelLoad := context.WithTimeout(shipCtx, 10*time.Second)
		var keySince int64
		if nets, pairs, ok := syncWiFiKeys(loadCtx, shipper, wifiProc.Keys(), log, &keySince); ok && nets > 0 {
			log.Info("loaded wifi keys from server", "networks", nets, "pairwise", pairs)
		}
		cancelLoad()
		syncSettings := func(ctx context.Context) {
			if !*remoteConfig {
				return
			}
			c, err := shipper.FetchConfig(ctx)
			if err != nil {
				// Keep doing what it's doing: a server that's down or too old
				// shouldn't change how the sensor behaves.
				log.Debug("fetch settings", "err", err)
				return
			}
			if settings.update(c) {
				log.Info("settings from the server", "in_effect", fmt.Sprintf("%+v", settings.summary()))
				r.RefreshHello()
			}
		}
		loadCtx, cancelLoad = context.WithTimeout(shipCtx, 5*time.Second)
		syncSettings(loadCtx)
		cancelLoad()
		go func() {
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				select {
				case <-shipCtx.Done():
					return
				case <-t.C:
					syncWiFiKeys(shipCtx, shipper, wifiProc.Keys(), log, &keySince)
					syncSettings(shipCtx)
				}
			}
		}()
	}

	// The table says what capture can't see. It has to stop, with what it's still holding
	// sent, before the shipper drains below.
	var tableDone chan struct{}
	if ctMode != conntrack.Off {
		table := &conntrack.Runner{
			Tracker: conntrack.Tracker{Mode: ctMode, Ignore: ignore},
			Read:    conntrack.Dump, Every: *conntrackEvery, Log: log,
			Emit: func(ev wire.Event) { out.Emit(ev) },
		}
		if err := table.Check(); err != nil {
			return err
		}
		tableDone = make(chan struct{})
		go func() { defer close(tableDone); table.Run(ctx) }()
		log.Info("reading the connection table", "mode", ctMode, "every", *conntrackEvery)
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
		openOne := func(spec string) (capture.Source, error) {
			n, err := sensor.ResolveInterface(strings.TrimSpace(spec))
			if err != nil {
				return nil, err
			}
			return capture.OpenLive(capture.LiveConfig{Interface: n, RingBytes: *ringMB << 20, Promiscuous: *promisc})
		}
		captureSpecs := strings.Split(*ifaces, ",")
		if !*captureOn {
			captureSpecs = nil
		}
		for _, spec := range captureSpecs {
			src, oerr := openOne(spec)
			if oerr != nil {
				for _, s := range sources {
					s.Close()
				}
				return oerr
			}
			idx := len(sources)
			reconnect := capture.NewReconnect(src, func() (capture.Source, error) { return openOne(spec) }, log)
			reconnect.OnReopen = func() {
				namesMu.Lock()
				if idx < len(liveNames) {
					liveNames[idx] = reconnect.Name()
				}
				namesMu.Unlock()
				r.RefreshHello()
			}
			sources = append(sources, reconnect)
			log.Info("capturing", "iface", reconnect.Name(), "link", linkName(reconnect.LinkType()))
		}
		hopCtx, stopHop := context.WithCancel(ctx)
		defer stopHop()
		if *wifiHop {
			channels := wifi.DefaultChannels()
			if *wifiChannels != "" {
				var perr error
				if channels, perr = wifi.ParseChannels(*wifiChannels); perr != nil {
					for _, s := range sources {
						s.Close()
					}
					return perr
				}
			}
			var frequencies []int
			if *wifiFreqs != "" {
				var perr error
				if frequencies, perr = wifi.ParseFrequencies(*wifiFreqs); perr != nil {
					for _, s := range sources {
						s.Close()
					}
					return perr
				}
			}
			if *wifi6 {
				frequencies = append(wifi.DefaultFrequencies(), wifi.SixGHzFrequencies()...)
			}
			started := 0
			for _, src := range sources {
				if !capture.IsWiFi(src.LinkType()) {
					continue
				}
				started++
				go func(iface string) {
					h := &wifi.Hopper{Interface: iface, Channels: channels, Frequencies: frequencies, Dwell: *wifiDwell, Logger: log}
					if err := h.Run(hopCtx); err != nil {
						log.Warn("wifi channel hopping", "iface", iface, "err", err)
					}
				}(src.Name())
			}
			if started == 0 {
				log.Warn("-wifi-hop was set but no capture interface is in monitor mode")
			}
		}
		err = r.RunLive(ctx, sources)
		stopHop()
	}
	if tableDone != nil {
		<-tableDone
	}
	if reverse != nil {
		// Stop lookups before the shipper drains: a lookup still in
		// flight is cancelled rather than emitted after the final batch.
		reverse.Close()
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

// syncWiFiKeys fetches the server's Wi-Fi keys, replaces the keyring's PMKs
// and WEP keys with them, and installs the pairwise keys it can re-derive
// from the stored handshake nonces. A handshake for a network with no PMK is
// skipped, since nothing can be derived without it. It is best-effort: a
// fetch error is logged at debug, the keys already held are kept, and the
// next refresh retries. It reports how many networks and pairwise keys it
// loaded, and whether the fetch succeeded.
func syncWiFiKeys(ctx context.Context, shipper *wire.Shipper, keys *wifi.Keyring, log *slog.Logger, since *int64) (networks, pairwise int, ok bool) {
	// Overlap by a minute: a record can be committed while the fetch is
	// in flight, and received timestamps are millisecond-granular.
	until := time.Now().Add(-time.Minute).UnixMilli()
	got, err := shipper.FetchWiFiKeysSince(ctx, *since)
	if err != nil {
		log.Debug("fetch wifi keys", "err", err)
		return 0, 0, false
	}
	*since = until
	sec := &wifi.Secrets{PMKs: map[string][]byte{}}
	for _, p := range got.PMKs {
		if b, err := hex.DecodeString(p.PMK); err == nil && len(b) == 32 && p.SSID != "" {
			sec.Add(p.SSID, b)
		}
	}
	for _, w := range got.WEP {
		if b, err := wifi.ParseWEPKey(w.Index, w.Key); err == nil {
			sec.WEP[w.Index] = b
		}
	}
	keys.SetSecrets(sec)
	loaded := 0
	for _, r := range got.Handshakes {
		an, err1 := hex.DecodeString(r.ANonce)
		sn, err2 := hex.DecodeString(r.SNonce)
		if err1 != nil || err2 != nil {
			continue
		}
		if ok, err := keys.LoadHandshakeCipher(r.BSSID, r.STA, r.SSID, an, sn, r.KeyVersion, r.Cipher); err == nil && ok {
			loaded++
		}
	}
	// Group keys arrive still wrapped with a client's KEK; unwrapping
	// re-derives that KEK from our own PMK.
	groups := 0
	for _, g := range got.GroupKeys {
		rec, ok := wifi.GroupKeyFromWire(g)
		if !ok {
			continue
		}
		if ok, err := keys.LoadGroupKey(rec); err == nil && ok {
			groups++
		}
	}
	log.Debug("synced wifi keys", "networks", len(sec.PMKs), "pairwise", loaded, "group", groups)
	return len(sec.PMKs), loaded, true
}

func linkName(link int) string {
	switch link {
	case capture.LinkEthernet:
		return "ethernet"
	case capture.LinkRaw:
		return "raw-ip"
	case capture.LinkIEEE80211:
		return "802.11"
	case capture.LinkIEEE80211Radiotap:
		return "802.11+radiotap"
	default:
		return strconv.Itoa(link)
	}
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

func newLevelLogger(level slog.Leveler, format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
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
	// own holds the exact connections the shipper opened. Matching those,
	// not every flow to the server address, keeps other devices' use of
	// the netgraph UI visible.
	own map[string]time.Time
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
	f := &selfFilter{host: u.Hostname(), port: uint16(p), ips: map[netip.Addr]bool{}, own: map[string]time.Time{}}
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

func (f *selfFilter) observe(local, remote netip.AddrPort) {
	f.mu.Lock()
	f.own[local.String()+"|"+remote.String()] = time.Now().Add(10 * time.Minute)
	f.mu.Unlock()
}

func (f *selfFilter) match(src, dst netip.AddrPort) bool {
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	key := src.String() + "|" + dst.String()
	if exp, ok := f.own[key]; ok && exp.After(now) {
		return true
	}
	for k, exp := range f.own {
		if !exp.After(now) {
			delete(f.own, k)
		}
	}
	return false
}
