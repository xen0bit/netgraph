package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/xen0bit/netgraph/internal/apiclient"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/store"
)

// backendFlags select where queries go: a server (-server) or a database
// file opened read-only (-db).
type backendFlags struct {
	server    string
	tokenFile string
	db        string
}

func (b *backendFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&b.server, "server", os.Getenv("NETGRAPH_SERVER"), "netgraph server URL; $NETGRAPH_SERVER")
	fs.StringVar(&b.tokenFile, "token-file", "", "file holding the server's read token (default $NETGRAPH_READ_TOKEN)")
	fs.StringVar(&b.db, "db", envOr("NETGRAPH_DB", "netgraph.db"), "database file, used when -server is not set; $NETGRAPH_DB")
}

// open returns the backend and a function releasing it.
func (b *backendFlags) open() (model.Backend, func(), error) {
	if b.server != "" {
		tok, err := readSecret(b.tokenFile, "NETGRAPH_READ_TOKEN")
		if err != nil {
			return nil, nil, err
		}
		return apiclient.NewClient(b.server, tok), func() {}, nil
	}
	if _, err := os.Stat(b.db); err != nil {
		return nil, nil, fmt.Errorf("no -server given and database %q: %w", b.db, err)
	}
	st, err := store.OpenReadOnly(b.db, store.Config{Logger: quietLogger()})
	if err != nil {
		return nil, nil, err
	}
	return st, func() { st.Close() }, nil
}

// openWritable is open for the commands that change something: through the
// API, or the database file itself, as `label` does (stop the server first,
// or it may not see the change).
func (b *backendFlags) openWritable() (model.Backend, func(), error) {
	if b.server != "" {
		return b.open()
	}
	st, err := store.Open(b.db, store.Config{Logger: quietLogger()})
	if err != nil {
		return nil, nil, err
	}
	return st, func() { st.Close() }, nil
}

// parseInterspersed parses flags wherever they appear among the arguments,
// so `note "text" -at TIME` means what it looks like. The flag package alone
// stops at the first argument that is not a flag. After "--", everything is
// an argument.
func parseInterspersed(fs *flag.FlagSet, args []string) error {
	var rest []string
	if i := slices.Index(args, "--"); i >= 0 {
		args, rest = args[:i], args[i+1:]
	}
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	return fs.Parse(append(append([]string{"--"}, pos...), rest...))
}

// filterFlags are the window and narrowing flags every query shares.
type filterFlags struct {
	from, to                  string
	device, ip, domain, proto string
	app, dir, asn, country    string
	port, limit, offset       int
	multicast                 bool
	fromSet, toSet            bool
}

func (f *filterFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.from, "from", "-1h", "window start: -15m, -2h, -7d, today, RFC 3339, '2026-10-25 14:00', unix ms")
	fs.StringVar(&f.to, "to", "now", "window end, same forms as -from")
	fs.StringVar(&f.device, "device", "", "device MAC, hostname or label (glob)")
	fs.StringVar(&f.ip, "ip", "", "address or CIDR on either side")
	fs.StringVar(&f.domain, "domain", "", "DNS name, SNI or HTTP host (glob)")
	fs.IntVar(&f.port, "port", 0, "server port (the service)")
	fs.StringVar(&f.proto, "proto", "", "tcp, udp, icmp or a protocol number")
	fs.StringVar(&f.app, "app", "", "application: tls, quic, http, dns, ...")
	fs.StringVar(&f.dir, "dir", "", "direction: out (devices connecting out), in (connections from outside), local or external")
	fs.StringVar(&f.asn, "asn", "", "the remote end's network: an AS number (13335 or AS13335); needs the server's -asn-file")
	fs.StringVar(&f.country, "cc", "", "the remote end's country: a two-letter code; needs the server's -asn-file")
	fs.BoolVar(&f.multicast, "multicast", false, "include multicast and broadcast traffic")
	fs.IntVar(&f.limit, "limit", 0, "maximum rows (0: default)")
	fs.IntVar(&f.offset, "offset", 0, "rows to skip, for paging")
}

// visited records which window flags the user gave explicitly, so -to
// without -from means the hour before -to rather than the hour before now.
func (f *filterFlags) visited(fs *flag.FlagSet) {
	fs.Visit(func(fl *flag.Flag) {
		switch fl.Name {
		case "from":
			f.fromSet = true
		case "to":
			f.toSet = true
		}
	})
}

func (f *filterFlags) filter() (model.Filter, error) {
	now := time.Now()
	to, err := model.ParseTime(f.to, now)
	if err != nil {
		return model.Filter{}, fmt.Errorf("-to: %w", err)
	}
	from := to.Add(-time.Hour)
	if f.fromSet || !f.toSet {
		if from, err = model.ParseTime(f.from, now); err != nil {
			return model.Filter{}, fmt.Errorf("-from: %w", err)
		}
	}
	if !from.Before(to) {
		return model.Filter{}, errors.New("-from must be before -to")
	}
	mf := model.Filter{From: from, To: to, Device: f.device, IP: f.ip, Domain: f.domain, Port: f.port, Proto: f.proto, App: f.app, Dir: f.dir, Multicast: f.multicast, Limit: f.limit, Offset: f.offset}
	if f.asn != "" {
		if mf.ASN, err = model.ParseASN(f.asn); err != nil {
			return model.Filter{}, fmt.Errorf("-asn: %w", err)
		}
	}
	if f.country != "" {
		if mf.Country, err = model.ParseCountry(f.country); err != nil {
			return model.Filter{}, fmt.Errorf("-cc: %w", err)
		}
	}
	return mf, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// etcCredential returns the path of /etc/netgraph/<file> as the packaged
// unit hands it over (LoadCredential=etc:/etc/netgraph names each copy
// etc_<file>), or "" when there is none. This is how the optional read
// token, Wi-Fi keys and TLS pair reach the server: systemd does not expand
// ${CREDENTIALS_DIRECTORY} inside values from an EnvironmentFile, so
// server.conf cannot point flags at them.
func etcCredential(file string) string {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return ""
	}
	p := filepath.Join(dir, "etc_"+file)
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// readSecret reads a token from a file, or from env when file is "".
func readSecret(file, env string) (string, error) {
	if file == "" {
		return os.Getenv(env), nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
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

func ctx() context.Context { return context.Background() }

// table writes rows in one of the output formats.
type table struct {
	head []string
	rows [][]string
}

func (t *table) add(cells ...string) { t.rows = append(t.rows, cells) }

func (t *table) write(w io.Writer, format string) error {
	switch format {
	case "csv":
		cw := csv.NewWriter(w)
		_ = cw.Write(t.head)
		for _, r := range t.rows {
			cells := make([]string, len(r))
			for i, c := range r {
				cells[i] = model.CSVText(c)
			}
			_ = cw.Write(cells)
		}
		return cw.Error()
	default:
		tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, strings.Join(t.head, "\t"))
		for _, r := range t.rows {
			fmt.Fprintln(tw, strings.Join(r, "\t"))
		}
		return tw.Flush()
	}
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func ts(msec int64) string {
	if msec == 0 {
		return "-"
	}
	return time.UnixMilli(msec).Local().Format("2006-01-02 15:04:05")
}

// clock is the time part of ts, empty for an unset time.
func clock(msec int64) string {
	if msec == 0 {
		return ""
	}
	return time.UnixMilli(msec).Local().Format("15:04:05")
}

func clip(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

func join(ss []string, n int) string {
	if len(ss) > n {
		return strings.Join(ss[:n], ",") + fmt.Sprintf(",+%d", len(ss)-n)
	}
	return strings.Join(ss, ",")
}
