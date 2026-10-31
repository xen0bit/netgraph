package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
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
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/store"
	"github.com/xen0bit/netgraph/internal/wifi"
	"github.com/xen0bit/netgraph/web"
)

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	db := fs.String("db", envOr("NETGRAPH_DB", "netgraph.db"), "database file; $NETGRAPH_DB")
	listen := fs.String("listen", envOr("NETGRAPH_LISTEN", ":8443"), "listen address; $NETGRAPH_LISTEN")
	tokenFile := fs.String("token-file", "", "file holding the sensors' ingest token (default $NETGRAPH_TOKEN)")
	readTokenFile := fs.String("read-token-file", etcCredential("read.token"), "file holding the token for queries and the web UI (default $NETGRAPH_READ_TOKEN; under the systemd unit, /etc/netgraph/read.token; none: open)")
	noAuth := fs.Bool("no-auth", false, "accept ingest without a token (trusted networks only)")
	cert := fs.String("tls-cert", etcCredential("tls.crt"), "TLS certificate (PEM); under the systemd unit, /etc/netgraph/tls.crt")
	key := fs.String("tls-key", etcCredential("tls.key"), "TLS key (PEM); under the systemd unit, /etc/netgraph/tls.key")
	wifiKeyFile := fs.String("wifi-key-file", envOr("NETGRAPH_WIFI_KEY_FILE", etcCredential("wifi.keys")), "WPA/WPA2 passphrases, PMKs and WEP keys served to sensors for Wi-Fi decryption; $NETGRAPH_WIFI_KEY_FILE; under the systemd unit, /etc/netgraph/wifi.keys")
	alertURL := fs.String("alert-webhook", envOr("NETGRAPH_ALERT_WEBHOOK", ""), "POST a JSON alert here when a new device joins the network; $NETGRAPH_ALERT_WEBHOOK")
	alertLearn := fs.String("alert-learn", "24h", "after the first sensor connects, learn the network this long before alerting on new devices")
	alertAnomalies := fs.String("alert-anomalies", "", "also POST anomalies at or above this severity: low, medium or high (default off)")
	alertKinds := fs.String("alert-anomaly-kinds", "", "comma-separated anomaly kinds to alert on (default: all kinds at the chosen severity)")
	// Not a systemd credential like the files above: credentials are
	// capped at about 1 MB together, and the table is several.
	asnFile := fs.String("asn-file", envOr("NETGRAPH_ASN_FILE", ""), "an iptoasn.com ip2asn-combined.tsv(.gz): name the network and country of remote addresses; reloaded on SIGHUP and when the file changes. Default: the table built into release binaries, if any; none: no table. $NETGRAPH_ASN_FILE")
	webDir := fs.String("web-dir", "", "serve the web UI from this directory instead of the embedded copy")
	maxDB := fs.Int("max-db-mb", 0, "run emergency retention when the database exceeds this many MiB (0: off)")
	trimRollups := fs.Bool("trim-rollups", false, "with -max-db-mb, allow emergency retention to delete the oldest rollups and facts too")
	raw := fs.String("raw-retention", "14d", "keep raw flows, DNS and observations this long")
	rollup := fs.String("rollup-retention", "180d", "keep hourly rollups and facts this long")
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
	var notifier *alert.Notifier
	var onNew func(store.NewDevice)
	if *alertAnomalies != "" && model.SeverityRank(*alertAnomalies) == 0 {
		return fmt.Errorf("-alert-anomalies: want low, medium or high")
	}
	if *alertAnomalies != "" && *alertURL == "" {
		return errors.New("-alert-anomalies needs -alert-webhook")
	}
	if *trimRollups && *maxDB <= 0 {
		return errors.New("-trim-rollups needs -max-db-mb")
	}
	if *alertURL != "" {
		if u, err := url.Parse(*alertURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("-alert-webhook: want an http(s) URL")
		}
		var kinds []string
		for _, k := range strings.Split(*alertKinds, ",") {
			if k = strings.TrimSpace(k); k != "" {
				kinds = append(kinds, k)
			}
		}
		notifier = alert.New(alert.Config{URL: *alertURL, Learn: learnD, AnomalyMin: *alertAnomalies, AnomalyKinds: kinds, Logger: log})
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
	st, err := store.Open(*db, store.Config{RawRetention: rawD, RollupRetention: rollD, FactGap: gapD, ExactMax: exactD, Logger: log, OnNewDevice: onNew,
		ASN: networks.Load})
	if err != nil {
		return err
	}
	defer st.Close()

	cfg := api.Config{Store: st, IngestToken: ingestTok, ReadToken: readTok, WiFi: wifiKeys, Web: web.FS, Logger: log}
	if notifier != nil {
		cfg.Alerts = notifier.Stats
	}
	if *webDir != "" {
		cfg.Web = os.DirFS(*webDir)
	}
	apiSrv := api.New(cfg)
	srv := &http.Server{
		Addr:              *listen,
		Handler:           apiSrv,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          nil,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go st.RunRetention(ctx, time.Hour)
	if notifier != nil {
		notifier.SetSince(st.FirstSensorSeen)
		go notifier.Run(ctx)
		log.Info("new-device alerts on", "learn", learnD)
		if *alertAnomalies != "" {
			go watchAnomalies(ctx, st, notifier, log)
			log.Info("anomaly alerts on", "minimum", *alertAnomalies)
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

// watchAnomalies checks the last hour every five minutes and hands new
// findings to the notifier, which applies its own cooldown.
func watchAnomalies(ctx context.Context, st *store.Store, n *alert.Notifier, log *slog.Logger) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			rep, err := st.Anomalies(ctx, model.Filter{From: now.Add(-time.Hour), To: now})
			if err != nil {
				if ctx.Err() == nil {
					log.Error("scan anomalies for alerts", "err", err)
				}
				continue
			}
			for _, a := range rep.Anomalies {
				n.NotifyAnomaly(a)
			}
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
