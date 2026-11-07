package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xen0bit/netgraph/internal/alert"
	"github.com/xen0bit/netgraph/internal/api"
	"github.com/xen0bit/netgraph/internal/asn"
	"github.com/xen0bit/netgraph/internal/buildinfo"
	"github.com/xen0bit/netgraph/internal/geo"
	"github.com/xen0bit/netgraph/internal/hass"
	"github.com/xen0bit/netgraph/internal/llm"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/sources"
	"github.com/xen0bit/netgraph/internal/store"
	"github.com/xen0bit/netgraph/internal/wifi"
	"github.com/xen0bit/netgraph/internal/wire"
	"github.com/xen0bit/netgraph/web"
)

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	db := fs.String("db", envOr("NETGRAPH_DB", "netgraph.db"), "database file; $NETGRAPH_DB")
	listen := fs.String("listen", envOr("NETGRAPH_LISTEN", ":8443"), "listen address; $NETGRAPH_LISTEN")
	tokenFile := fs.String("token-file", "", "file holding the sensors' ingest token (default $NETGRAPH_TOKEN)")
	readTokenFile := fs.String("read-token-file", etcCredential("read.token"), "file holding the token for queries and the web UI (default $NETGRAPH_READ_TOKEN; under the systemd unit, /etc/netgraph/read.token; none: open)")
	operatorTokenFile := fs.String("operator-token-file", "", "file holding the token for changing things: labels, notes, findings. With this set, the read token only reads; default $NETGRAPH_OPERATOR_TOKEN")
	adminTokenFile := fs.String("admin-token-file", "", "file holding the token for the audit log and test notifications; default $NETGRAPH_ADMIN_TOKEN")
	agentTokenFile := fs.String("agent-token-file", etcCredential("agent.token"), "file holding the optional host agents' token (default $NETGRAPH_AGENT_TOKEN; under the systemd unit, /etc/netgraph/agent.token; none: agents off)")
	trustedProxy := fs.String("trusted-proxy", "", "comma-separated addresses or CIDRs of a reverse proxy to trust to say who someone is")
	proxyHeader := fs.String("proxy-user-header", "Remote-User", "the header a -trusted-proxy names the user in")
	proxyRoles := fs.String("proxy-roles-file", "", `with -trusted-proxy, lines of "user role" (viewer, operator or admin); "* role" sets the default, otherwise viewer`)
	noAuth := fs.Bool("no-auth", false, "accept ingest without a token (trusted networks only)")
	cert := fs.String("tls-cert", etcCredential("tls.crt"), "TLS certificate (PEM); under the systemd unit, /etc/netgraph/tls.crt")
	key := fs.String("tls-key", etcCredential("tls.key"), "TLS key (PEM); under the systemd unit, /etc/netgraph/tls.key")
	wifiKeyFile := fs.String("wifi-key-file", envOr("NETGRAPH_WIFI_KEY_FILE", etcCredential("wifi.keys")), "WPA/WPA2 passphrases, PMKs and WEP keys served to sensors for Wi-Fi decryption; $NETGRAPH_WIFI_KEY_FILE; under the systemd unit, /etc/netgraph/wifi.keys")
	alertURL := fs.String("alert-webhook", envOr("NETGRAPH_ALERT_WEBHOOK", ""), "POST a JSON alert here when a new device joins the network; $NETGRAPH_ALERT_WEBHOOK")
	alertLearn := fs.String("alert-learn", "24h", "after the first sensor connects, learn the network this long before alerting on new devices")
	notifyFile := fs.String("notify-file", "", "file of notification channels, one URL a line: ntfy://, gotify://, telegram://, smtp://, https://; or $NETGRAPH_NOTIFY")
	mqttFile := fs.String("mqtt-file", "", "file holding an MQTT broker's URL, to publish to Home Assistant: mqtt://user:pass@host:1883/prefix; or $NETGRAPH_MQTT")
	netflowListen := fs.String("netflow-listen", "", "receive NetFlow v5, v9 and IPFIX on this UDP address, such as :2055 (needs -netflow-allow)")
	netflowAllow := fs.String("netflow-allow", "", "comma-separated addresses or CIDRs to accept exports from")
	sflowListen := fs.String("sflow-listen", "", "receive sFlow v5 on this UDP address, such as :6343 (needs -sflow-allow)")
	sflowAllow := fs.String("sflow-allow", "", "comma-separated addresses or CIDRs to accept sFlow from")
	dnsLog := fs.String("dns-log", "", "follow this DNS server's log: dnsmasq's log-queries output, Pi-hole's pihole.log, or AdGuard Home's querylog.json")
	dnsLogFormat := fs.String("dns-log-format", "dnsmasq", "dnsmasq (also Pi-hole) or adguard")
	leasesFile := fs.String("leases-file", "", "read device names and addresses from this DHCP server's lease file")
	leasesFormat := fs.String("leases-format", "dnsmasq", "dnsmasq, isc (dhcpd.leases, also OPNsense and pfSense) or kea (memfile CSV)")
	sourceLocal := fs.String("source-local", "", "comma-separated CIDRs that are \"here\", for -netflow-listen, -sflow-listen, -dns-log and -leases-file (default the private ranges)")
	llmFile := fs.String("llm-file", "", "file holding an OpenAI-compatible model's URL, to let Ask use it: http://localhost:11434/v1?model=llama3.2; or $NETGRAPH_LLM. Off by default: a model elsewhere receives your network's data")
	alertAnomalies := fs.String("alert-anomalies", "", "also POST anomalies at or above this severity: low, medium or high (default off)")
	alertKinds := fs.String("alert-anomaly-kinds", "", "comma-separated anomaly kinds to alert on (default: all kinds at the chosen severity)")
	reportEvery := fs.String("report-every", envOr("NETGRAPH_REPORT_EVERY", ""), "POST a summary report at this interval, e.g. 24h (needs -alert-webhook); $NETGRAPH_REPORT_EVERY")
	// Not a systemd credential like the files above: credentials are
	// capped at about 1 MB together, and the table is several.
	geoFile := fs.String("geo-file", envOr("NETGRAPH_GEO_FILE", ""), "a local CSV of address ranges to city/region/organisation; empty: no geo lookup. $NETGRAPH_GEO_FILE")
	asnFile := fs.String("asn-file", envOr("NETGRAPH_ASN_FILE", ""), "an iptoasn.com ip2asn-combined.tsv(.gz): name the network and country of remote addresses; reloaded on SIGHUP and when the file changes. Default: the table built into release binaries, if any; none: no table. $NETGRAPH_ASN_FILE")
	webDir := fs.String("web-dir", "", "serve the web UI from this directory instead of the embedded copy")
	maxDB := fs.Int("max-db-mb", 0, "run emergency retention when the database exceeds this many MiB (0: off)")
	trimRollups := fs.Bool("trim-rollups", false, "with -max-db-mb, allow emergency retention to delete the oldest rollups and facts too")
	raw := fs.String("raw-retention", "14d", "keep raw flows, DNS and observations this long")
	rollup := fs.String("rollup-retention", "180d", "keep hourly rollups and facts this long")
	minute := fs.String("minute-retention", "30d", "keep per-minute traffic, which the timeline scrubs through, this long")
	archiveDir := fs.String("archive-dir", envOr("NETGRAPH_ARCHIVE_DIR", ""), "keep hourly rollups in compressed files here as they pass -rollup-retention; $NETGRAPH_ARCHIVE_DIR")
	archiveRaw := fs.Bool("archive-raw", false, "with -archive-dir, also keep raw connections and lookups as they pass -raw-retention: much larger, and far more detailed")
	archiveMax := fs.Int("archive-max-mb", 0, "with -archive-dir, remove the oldest days beyond this many MiB (default no limit)")
	gap := fs.String("fact-gap", "1h", "silence after which a relationship starts a new period")
	exactMax := fs.String("exact-max", "48h", "longest window answered from raw records; longer ones use hourly rollups")
	logLevel := fs.String("log-level", "info", "debug, info, warn or error")
	logFormat := fs.String("log-format", "text", "text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := newLogger(*logLevel, *logFormat)
	if (*cert == "") != (*key == "") {
		return errors.New("-tls-cert and -tls-key go together")
	}
	ingestTok, err := readSecret(*tokenFile, "NETGRAPH_TOKEN")
	if err != nil {
		return err
	}
	readTok, err := readSecret(*readTokenFile, "NETGRAPH_READ_TOKEN")
	if err != nil {
		return err
	}
	operatorTok, err := readSecret(*operatorTokenFile, "NETGRAPH_OPERATOR_TOKEN")
	if err != nil {
		return err
	}
	adminTok, err := readSecret(*adminTokenFile, "NETGRAPH_ADMIN_TOKEN")
	if err != nil {
		return err
	}
	agentTok, err := readSecret(*agentTokenFile, "NETGRAPH_AGENT_TOKEN")
	if err != nil {
		return err
	}
	proxy, err := readProxyAuth(*trustedProxy, *proxyHeader, *proxyRoles)
	if err != nil {
		return err
	}
	if ingestTok == "" && !*noAuth {
		return errors.New("no ingest token: set $NETGRAPH_TOKEN or -token-file (or pass -no-auth on a trusted network)")
	}
	var wifiKeys *wifi.Secrets
	if *wifiKeyFile != "" {
		if ingestTok == "" {
			return errors.New("-wifi-key-file needs an ingest token: Wi-Fi keys are only served to authenticated sensors")
		}
		if wifiKeys, err = wifi.LoadKeyFile(*wifiKeyFile); err != nil {
			return fmt.Errorf("wifi keys: %w", err)
		}
	}
	rawD, err := model.ParseDuration(*raw)
	if err != nil {
		return fmt.Errorf("-raw-retention: %w", err)
	}
	minuteD, err := model.ParseDuration(*minute)
	if err != nil {
		return fmt.Errorf("-minute-retention: %w", err)
	}
	rollD, err := model.ParseDuration(*rollup)
	if err != nil {
		return fmt.Errorf("-rollup-retention: %w", err)
	}
	gapD, err := model.ParseDuration(*gap)
	if err != nil {
		return fmt.Errorf("-fact-gap: %w", err)
	}
	exactD, err := model.ParseDuration(*exactMax)
	if err != nil {
		return fmt.Errorf("-exact-max: %w", err)
	}
	learnD, err := model.ParseDuration(*alertLearn)
	if err != nil {
		return fmt.Errorf("-alert-learn: %w", err)
	}
	var reportD time.Duration
	if *reportEvery != "" {
		reportD, err = model.ParseDuration(*reportEvery)
		if err != nil {
			return fmt.Errorf("-report-every: %w", err)
		}
		if reportD <= 0 {
			return errors.New("-report-every must be positive")
		}
	}
	if reportD > 0 && *alertURL == "" {
		return errors.New("-report-every needs -alert-webhook or -notify-file")
	}
	var notifier *alert.Notifier
	var onNew func(store.NewDevice)
	if *alertAnomalies != "" && model.SeverityRank(*alertAnomalies) == 0 {
		return fmt.Errorf("-alert-anomalies: want low, medium or high")
	}
	routes, err := readChannels(*notifyFile)
	if err != nil {
		return err
	}
	if *alertAnomalies != "" && *alertURL == "" && len(routes) == 0 {
		return errors.New("-alert-anomalies needs -alert-webhook or -notify-file")
	}
	bridge, err := readBridge(*mqttFile, log)
	if err != nil {
		return err
	}
	askModel, err := readLLM(*llmFile, log)
	if err != nil {
		return err
	}
	allowExporters, err := parsePrefixes("-netflow-allow", *netflowAllow)
	if err != nil {
		return err
	}
	if *netflowListen != "" && len(allowExporters) == 0 {
		return errors.New("-netflow-listen needs -netflow-allow: UDP has no login, so this says who to believe")
	}
	allowSFlow, err := parsePrefixes("-sflow-allow", *sflowAllow)
	if err != nil {
		return err
	}
	if *sflowListen != "" && len(allowSFlow) == 0 {
		return errors.New("-sflow-listen needs -sflow-allow: UDP has no login, so this says who to believe")
	}
	if !sources.ValidLeaseFormat(*leasesFormat) {
		return fmt.Errorf("-leases-format: %q is not dnsmasq, isc or kea", *leasesFormat)
	}
	localNets, err := parsePrefixes("-source-local", *sourceLocal)
	if err != nil {
		return err
	}
	if !sources.ValidDNSLogFormat(*dnsLogFormat) {
		return fmt.Errorf("-dns-log-format: %q is not dnsmasq or adguard", *dnsLogFormat)
	}
	if *trimRollups && *maxDB <= 0 {
		return errors.New("-trim-rollups needs -max-db-mb")
	}
	if *maxDB < 0 {
		return errors.New("-max-db-mb must not be negative")
	}
	if *alertURL != "" || len(routes) > 0 {
		if *alertURL != "" {
			if u, err := url.Parse(*alertURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("-alert-webhook: want an http(s) URL")
			}
		}
		var kinds []string
		for _, k := range strings.Split(*alertKinds, ",") {
			if k = strings.TrimSpace(k); k != "" {
				kinds = append(kinds, k)
			}
		}
		notifier = alert.New(alert.Config{URL: *alertURL, Learn: learnD, AnomalyMin: *alertAnomalies, AnomalyKinds: kinds, Routes: routes, Logger: log})
		onNew = notifier.Notify
	}
	// The ASN table: a file given (reloaded when it changes), else the one
	// built into release binaries, else none.
	var networks atomic.Pointer[asn.DB]
	switch *asnFile {
	case "none":
		*asnFile = ""
	case "":
		t0 := time.Now()
		table, date, err := asn.Embedded()
		switch {
		case err != nil:
			log.Error("built-in asn table; running without one", "err", err)
		case table != nil:
			networks.Store(table)
			debug.FreeOSMemory()
			log.Info("using the built-in asn table; -asn-file for a newer one", "downloaded", date, "ranges", table.Len(), "took", time.Since(t0).Round(time.Millisecond))
		}
	default:
		t0 := time.Now()
		table, err := asn.Load(*asnFile)
		if err != nil {
			return fmt.Errorf("-asn-file: %w", err)
		}
		networks.Store(table)
		debug.FreeOSMemory() // parsing left several times the table's size behind
		log.Info("loaded asn table", "file", *asnFile, "ranges", table.Len(), "took", time.Since(t0).Round(time.Millisecond))
	}
	var geoTable atomic.Pointer[geo.DB]
	if *geoFile != "" {
		f, err := os.Open(*geoFile)
		if err != nil {
			return fmt.Errorf("-geo-file: %w", err)
		}
		db, err := geo.Parse(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("-geo-file: %w", err)
		}
		geoTable.Store(db)
		log.Info("loaded geo table", "file", *geoFile, "ranges", db.Len())
	}
	if (*archiveRaw || *archiveMax > 0) && *archiveDir == "" {
		return errors.New("-archive-raw and -archive-max-mb need -archive-dir")
	}
	st, err := store.Open(*db, store.Config{ArchiveDir: *archiveDir, ArchiveRaw: *archiveRaw, ArchiveMaxBytes: int64(*archiveMax) << 20, RawRetention: rawD, RollupRetention: rollD, MinuteRetention: minuteD, FactGap: gapD, ExactMax: exactD, Logger: log, OnNewDevice: onNew,
		ASN: networks.Load, Geo: geoTable.Load})
	if err != nil {
		return err
	}
	defer st.Close()

	cfg := api.Config{Store: st, IngestToken: ingestTok, ReadToken: readTok, OperatorToken: operatorTok, AdminToken: adminTok, AgentToken: agentTok, Proxy: proxy, WiFi: wifiKeys, Web: web.FS, Logger: log}
	if notifier != nil { // not a nil pointer in an interface
		cfg.Notify = notifier
	}
	cfg.LLM = askModel
	if notifier != nil {
		cfg.Alerts = notifier.Stats
	}
	if *webDir != "" {
		if info, err := os.Stat(*webDir); err != nil || !info.IsDir() {
			return fmt.Errorf("-web-dir %q is not a directory", *webDir)
		}
		cfg.Web = os.DirFS(*webDir)
	}
	apiSrv := api.New(cfg)
	srv := &http.Server{
		Addr:              *listen,
		Handler:           apiSrv,
		ReadHeaderTimeout: 10 * time.Second,
		// Ingest bodies get their own deadline in the handler; a blanket
		// ReadTimeout would cut off large batches from slow sensors.
		ReadTimeout:    0,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 1 << 20,
		ErrorLog:       nil,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go reloadTokens(ctx, apiSrv, *tokenFile, *readTokenFile, *operatorTokenFile, *adminTokenFile, *agentTokenFile, *noAuth, log)
	go st.RunRetention(ctx, time.Hour)
	sink := func(ctx context.Context, sensor, boot string, evs []wire.Event) error {
		_, err := st.Ingest(ctx, sensor, boot, evs)
		return err
	}
	if *netflowListen != "" {
		go func() {
			n := &sources.NetFlow{Listen: *netflowListen, Allow: allowExporters, Local: localNets, Sink: sink, Log: log}
			if err := n.Run(ctx); err != nil && ctx.Err() == nil {
				log.Error("netflow", "err", err)
			}
		}()
		log.Info("receiving NetFlow", "listen", *netflowListen)
	}
	if *sflowListen != "" {
		go func() {
			n := &sources.SFlow{Listen: *sflowListen, Allow: allowSFlow, Local: localNets, Sink: sink, Log: log}
			if err := n.Run(ctx); err != nil && ctx.Err() == nil {
				log.Error("sflow", "err", err)
			}
		}()
		log.Info("receiving sFlow", "listen", *sflowListen)
	}
	if *dnsLog != "" {
		go func() {
			d := &sources.DNSLog{Path: *dnsLog, Format: *dnsLogFormat, Local: localNets, Sink: sink, Log: log}
			if err := d.Run(ctx); err != nil && ctx.Err() == nil {
				log.Error("dns log", "err", err)
			}
		}()
		log.Info("following a DNS log", "path", *dnsLog, "format", *dnsLogFormat)
	}
	if *leasesFile != "" {
		go func() {
			if err := (&sources.LeaseFile{Path: *leasesFile, Format: *leasesFormat, Local: localNets, Sink: sink, Log: log}).Run(ctx); err != nil && ctx.Err() == nil {
				log.Error("lease file", "err", err)
			}
		}()
		log.Info("reading a lease file", "path", *leasesFile, "format", *leasesFormat)
	}
	var anomalyAlerts *alert.Notifier
	if notifier != nil && *alertAnomalies != "" {
		anomalyAlerts = notifier
	}
	if bridge != nil {
		b := hass.New(*bridge, st)
		go b.Run(ctx)
		go scanFindings(ctx, st, anomalyAlerts, b, log)
		log.Info("publishing to Home Assistant over MQTT", "addr", bridge.Options.Addr)
	} else {
		go scanFindings(ctx, st, anomalyAlerts, nil, log)
	}
	if notifier != nil {
		notifier.SetSince(st.FirstSensorSeen)
		go notifier.Run(ctx)
		log.Info("new-device alerts on", "learn", learnD)
		if *alertAnomalies != "" {
			log.Info("anomaly alerts on", "minimum", *alertAnomalies)
		}
		if reportD > 0 {
			go reportLoop(ctx, st, notifier, reportD, log)
			log.Info("scheduled reports on", "every", reportD)
		}
	}
	if *maxDB > 0 {
		go diskGuard(ctx, st, int64(*maxDB)<<20, *trimRollups, log)
		log.Info("database disk guard on", "max_mb", *maxDB, "trim_rollups", *trimRollups)
	}
	if *wifiKeyFile != "" {
		go reloadWiFiKeys(ctx, *wifiKeyFile, apiSrv, log)
	}
	if networks.Load() != nil {
		go enrichASN(ctx, st, log)
	}
	if *asnFile != "" {
		go reloadASN(ctx, *asnFile, &networks, st, log)
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	scheme := "http"
	if *cert != "" {
		scheme = "https"
	}
	if readTok == "" {
		if host, _, _ := net.SplitHostPort(*listen); host == "" || !net.ParseIP(host).IsLoopback() {
			log.Warn("queries and the web UI are open to anyone who can reach this port; set $NETGRAPH_READ_TOKEN to require a token")
		}
	}
	if wifiKeys != nil {
		log.Info("serving wifi keys to sensors", "networks", len(wifiKeys.PMKs))
		if *cert == "" {
			log.Warn("wifi keys are sent to sensors without TLS; use -tls-cert, or a TLS proxy, unless the sensor link is trusted")
		}
	}
	if cfg.Web == nil {
		log.Warn("this build has no web UI embedded; use -web-dir or a release build")
	}
	if *archiveDir == "" {
		if dir, err := st.RecordedArchive(ctx); err == nil && dir != "" {
			log.Warn("this database has an archive, but -archive-dir isn't set: what passes retention now is deleted, not kept. db forget and db purge still reach it", "dir", dir)
		}
	}
	log.Info("netgraph serving", "version", buildinfo.Version, "listen", scheme+"://"+ln.Addr().String(), "db", *db)
	errc := make(chan error, 1)
	go func() {
		if *cert != "" {
			errc <- srv.ServeTLS(ln, *cert, *key)
		} else {
			errc <- srv.Serve(ln)
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	// SSE responses never become idle, so close them explicitly before
	// waiting for the HTTP server.
	apiSrv.Shutdown()
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

// diskGuard keeps a hard ceiling on the database. It runs early retention
// first; if the file is still too large it removes the oldest raw rows,
// optionally including rollups. It is a last resort for a full disk, not a
// replacement for the configured retention policy.
func diskGuard(ctx context.Context, st *store.Store, target int64, trimRollups bool, log *slog.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if st.Size() <= target {
				continue
			}
			log.Warn("database over disk guard; trimming oldest data", "bytes", st.Size(), "target", target)
			if _, err := st.Retain(ctx); err != nil {
				log.Error("disk guard retention", "err", err)
			}
			if st.Size() > target {
				r, err := st.EmergencyTrim(ctx, target, trimRollups)
				if err != nil {
					log.Error("disk guard emergency trim", "err", err)
					continue
				}
				log.Warn("emergency trim complete", "flows", r.Flows, "dns", r.DNS, "facts", r.Facts, "rollups", r.Rollups, "bytes", st.Size())
			}
			if st.Size() > target {
				log.Error("database still over disk guard after trim", "bytes", st.Size(), "target", target)
			}
		}
	}
}

// reportLoop posts a window summary on a schedule. It runs on the same
// webhook as alerts and uses the current window, so a 24h report covers the
// last day, not a calendar day.
func reportLoop(ctx context.Context, st *store.Store, n *alert.Notifier, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			f := model.Filter{From: now.Add(-every), To: now}
			sum, err := st.Summary(ctx, f)
			if err != nil {
				if ctx.Err() == nil {
					log.Error("scheduled report summary", "err", err)
				}
				continue
			}
			rep, err := st.Anomalies(ctx, f)
			if err != nil && ctx.Err() == nil {
				log.Error("scheduled report anomalies", "err", err)
			}
			var b strings.Builder
			fmt.Fprintf(&b, "netgraph report for the last %s: %d devices, %d connections, %s sent, %s received",
				every, sum.Devices, sum.Flows, model.FormatBytes(sum.BytesOut), model.FormatBytes(sum.BytesIn))
			if rep != nil {
				if rep.Learning {
					b.WriteString("; still learning history")
				}
				if len(rep.Anomalies) > 0 {
					fmt.Fprintf(&b, "; %d anomalies", len(rep.Anomalies))
					for i, a := range rep.Anomalies {
						if i == 5 {
							break
						}
						fmt.Fprintf(&b, "\n- [%s] %s", a.Severity, a.Summary)
					}
				}
			}
			n.NotifyReport(b.String())
		}
	}
}

// scanFindings records what the checks find, now and every five minutes, so that a
// finding has a history whether or not anyone is looking. Alerts follow from it: a
// finding pages when it's new and when it comes back, not while it simply continues.
func scanFindings(ctx context.Context, st *store.Store, n *alert.Notifier, b *hass.Bridge, log *slog.Logger) {
	scan := func() {
		events, err := st.ScanFindings(ctx)
		if err != nil {
			if ctx.Err() == nil {
				log.Error("scan for findings", "err", err)
			}
			return
		}
		announceFindings(events, n, b)
	}
	scan()
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			scan()
		}
	}
}

// announceFindings tells whoever's listening what a scan changed.
func announceFindings(events []store.FindingEvent, n *alert.Notifier, b *hass.Bridge) {
	for _, e := range events {
		if n != nil {
			n.NotifyAnomaly(e.Finding.Anomaly)
		}
		if b != nil {
			b.Finding(e.Type, e.Finding)
		}
	}
}

// readChannels reads notification channels from a file or the environment, one URL
// a line. They hold tokens, so they don't belong in flags, which ps shows, and the
// errors say which line and never what's on it.
func readChannels(file string) ([]alert.Route, error) {
	text := os.Getenv("NETGRAPH_NOTIFY")
	where := "$NETGRAPH_NOTIFY"
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("-notify-file: %w", err)
		}
		text, where = string(b), "-notify-file"
	}
	var routes []alert.Route
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r, err := alert.ParseChannel(line, nil)
		if err != nil {
			return nil, fmt.Errorf("%s, line %d: %w", where, i+1, err)
		}
		routes = append(routes, r)
	}
	return routes, nil
}

// readBridge reads the MQTT broker's URL from a file or the environment; it holds a
// password, as above. Nil means Home Assistant isn't wanted.
func readBridge(file string, log *slog.Logger) (*hass.Config, error) {
	raw := os.Getenv("NETGRAPH_MQTT")
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("-mqtt-file: %w", err)
		}
		raw = string(b)
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	c, err := hass.ParseURL(raw)
	if err != nil {
		return nil, fmt.Errorf("mqtt: %w", err)
	}
	c.Logger = log
	if c.Options.Password != "" && c.Options.TLS == nil {
		log.Warn("the MQTT password will cross the network in the clear; use mqtts:// unless the broker is on this machine")
	}
	return &c, nil
}

// parsePrefixes reads comma-separated addresses and CIDRs.
func parsePrefixes(flagName, list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, t := range strings.Split(list, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		pre, err := netip.ParsePrefix(t)
		if err != nil {
			a, aerr := netip.ParseAddr(t)
			if aerr != nil {
				return nil, fmt.Errorf("%s: %q is not an address or CIDR", flagName, t)
			}
			pre = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, pre.Masked())
	}
	return out, nil
}

// readProxyAuth reads who to trust to say who someone is. Nil if nobody.
func readProxyAuth(trusted, header, rolesFile string) (*api.ProxyAuth, error) {
	if strings.TrimSpace(trusted) == "" {
		if rolesFile != "" {
			return nil, errors.New("-proxy-roles-file needs -trusted-proxy")
		}
		return nil, nil
	}
	p := &api.ProxyAuth{Header: header, Roles: map[string]api.Role{}, Default: api.RoleViewer}
	var err error
	if p.Trusted, err = parsePrefixes("-trusted-proxy", trusted); err != nil {
		return nil, err
	}
	if rolesFile == "" {
		return p, nil
	}
	b, err := os.ReadFile(rolesFile)
	if err != nil {
		return nil, fmt.Errorf("-proxy-roles-file: %w", err)
	}
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			return nil, fmt.Errorf("-proxy-roles-file, line %d: want \"user role\"", i+1)
		}
		role, ok := api.ParseRole(f[1])
		if !ok {
			return nil, fmt.Errorf("-proxy-roles-file, line %d: a role is viewer, operator or admin", i+1)
		}
		if f[0] == "*" {
			p.Default = role
		} else {
			p.Roles[f[0]] = role
		}
	}
	return p, nil
}

// readLLM reads the language model's URL from a file or the environment; it can hold
// a key. Nil means there's none, which is the default.
func readLLM(file string, log *slog.Logger) (*llm.Config, error) {
	raw := os.Getenv("NETGRAPH_LLM")
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("-llm-file: %w", err)
		}
		raw = string(b)
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	c, err := llm.ParseURL(raw)
	if err != nil {
		return nil, fmt.Errorf("llm: %w", err)
	}
	if c.Local() {
		log.Info("Ask can use a language model", "model", c.Model, "host", c.Host())
	} else {
		log.Warn("Ask can use a language model on another network: questions asked with it send network data there", "model", c.Model, "host", c.Host())
	}
	return &c, nil
}

// reloadTokens re-reads the token files on SIGHUP. A failed read keeps the
// previous credentials; a flag with no file and no environment variable is
// left alone rather than silently becoming open.
func reloadTokens(ctx context.Context, srv *api.Server, ingestFile, readFile, operatorFile, adminFile, agentFile string, noAuth bool, log *slog.Logger) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			ingest, read := srv.Tokens()
			if !noAuth && (ingestFile != "" || os.Getenv("NETGRAPH_TOKEN") != "") {
				v, err := readSecret(ingestFile, "NETGRAPH_TOKEN")
				if err != nil {
					log.Error("reload ingest token; keeping the previous one", "err", err)
				} else {
					ingest = v
				}
			}
			if readFile != "" || os.Getenv("NETGRAPH_READ_TOKEN") != "" {
				v, err := readSecret(readFile, "NETGRAPH_READ_TOKEN")
				if err != nil {
					log.Error("reload read token; keeping the previous one", "err", err)
				} else {
					read = v
				}
			}
			srv.SetTokens(ingest, read)
			operator, err := readSecret(operatorFile, "NETGRAPH_OPERATOR_TOKEN")
			if err != nil {
				log.Error("reload operator token; keeping the role tokens", "err", err)
				continue
			}
			admin, err := readSecret(adminFile, "NETGRAPH_ADMIN_TOKEN")
			if err != nil {
				log.Error("reload admin token; keeping the role tokens", "err", err)
				continue
			}
			srv.SetRoleTokens(operator, admin)
			if agentFile != "" || os.Getenv("NETGRAPH_AGENT_TOKEN") != "" {
				agent, err := readSecret(agentFile, "NETGRAPH_AGENT_TOKEN")
				if err != nil {
					log.Error("reload agent token; keeping the previous one", "err", err)
				} else {
					srv.SetAgentToken(agent)
				}
			}
			log.Info("reloaded tokens")
		}
	}
}

// reloadWiFiKeys re-reads the Wi-Fi key file on SIGHUP, so adding or
// revoking a network's key needs no restart. A file that fails to parse is
// logged and the keys already loaded stay in use.
func reloadWiFiKeys(ctx context.Context, path string, srv *api.Server, log *slog.Logger) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			sec, err := wifi.LoadKeyFile(path)
			if err != nil {
				log.Error("reload wifi keys; keeping the previous keys", "file", path, "err", err)
				continue
			}
			srv.SetWiFi(sec)
			log.Info("reloaded wifi keys", "networks", len(sec.PMKs))
		}
	}
}

// enrichASN looks up the network of remote ends stored while no ASN table
// was loaded.
func enrichASN(ctx context.Context, st *store.Store, log *slog.Logger) {
	t0 := time.Now()
	n, err := st.EnrichASN(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Error("look up networks", "err", err)
		}
		return
	}
	if n > 0 {
		log.Info("looked up networks", "rows", n, "took", time.Since(t0).Round(time.Millisecond))
	}
}

// asnCheck is how often the server looks for a newer ASN file.
const asnCheck = 5 * time.Minute

// reloadASN re-reads the ASN table on SIGHUP, or when the file's
// modification time changes (a timer replaced it). A file that fails to
// parse is logged and the table already loaded stays in use.
func reloadASN(ctx context.Context, path string, networks *atomic.Pointer[asn.DB], st *store.Store, log *slog.Logger) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	tick := time.NewTicker(asnCheck)
	defer tick.Stop()
	mtime := func() time.Time {
		fi, err := os.Stat(path)
		if err != nil {
			return time.Time{}
		}
		return fi.ModTime()
	}
	loaded := mtime()
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
		case <-tick.C:
			if m := mtime(); m.IsZero() || m.Equal(loaded) {
				continue
			}
		}
		loaded = mtime()
		table, err := asn.Load(path)
		if err != nil {
			log.Error("reload asn table; keeping the previous one", "file", path, "err", err)
			continue
		}
		networks.Store(table)
		debug.FreeOSMemory()
		log.Info("reloaded asn table", "ranges", table.Len())
		enrichASN(ctx, st, log)
	}
}
