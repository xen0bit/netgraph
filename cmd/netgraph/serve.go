package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xen0bit/netgraph/internal/api"
	"github.com/xen0bit/netgraph/internal/buildinfo"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/store"
	"github.com/xen0bit/netgraph/web"
)

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	db := fs.String("db", envOr("NETGRAPH_DB", "netgraph.db"), "database file; $NETGRAPH_DB")
	listen := fs.String("listen", envOr("NETGRAPH_LISTEN", ":8443"), "listen address; $NETGRAPH_LISTEN")
	tokenFile := fs.String("token-file", "", "file holding the sensors' ingest token (default $NETGRAPH_TOKEN)")
	readTokenFile := fs.String("read-token-file", "", "file holding the token for queries and the web UI (default $NETGRAPH_READ_TOKEN; none: open)")
	noAuth := fs.Bool("no-auth", false, "accept ingest without a token (trusted networks only)")
	cert := fs.String("tls-cert", "", "TLS certificate (PEM)")
	key := fs.String("tls-key", "", "TLS key (PEM)")
	webDir := fs.String("web-dir", "", "serve the web UI from this directory instead of the embedded copy")
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
	st, err := store.Open(*db, store.Config{RawRetention: rawD, RollupRetention: rollD, FactGap: gapD, ExactMax: exactD, Logger: log})
	if err != nil {
		return err
	}
	defer st.Close()

	cfg := api.Config{Store: st, IngestToken: ingestTok, ReadToken: readTok, Web: web.FS, Logger: log}
	if *webDir != "" {
		cfg.Web = os.DirFS(*webDir)
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           api.New(cfg),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          nil,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go st.RunRetention(ctx, time.Hour)

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
