// Package api is netgraph's HTTP interface: sensors post event batches to
// it, and the CLI, TUI and web UI query it. Client is the matching
// model.Backend, so a remote server and a local database file answer the
// same calls.
package api

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/buildinfo"
	"github.com/xen0bit/netgraph/internal/graph"
	"github.com/xen0bit/netgraph/internal/graph/d2render"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/store"
	"github.com/xen0bit/netgraph/internal/wifi"
	"github.com/xen0bit/netgraph/internal/wire"
)

// Config configures a Server.
type Config struct {
	Store *store.Store
	// IngestToken authenticates sensors; ReadToken authenticates queries.
	// An empty token disables that check.
	IngestToken string
	ReadToken   string
	// Web is the web UI's files (index.html, web.wasm[.gz], ...); nil
	// serves a page saying the UI was not built in.
	Web    fs.FS
	Logger *slog.Logger
	// WiFi holds the Wi-Fi keys served to sensors; nil serves none. They
	// are only served when IngestToken is set.
	WiFi *wifi.Secrets
	// MaxBatch bounds an ingest request body (compressed); default 32 MiB.
	MaxBatch int64
}

// Server serves the API.
type Server struct {
	cfg Config
	mux *http.ServeMux
	log *slog.Logger
}

// New returns a Server.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = 32 << 20
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux(), log: cfg.Logger}
	s.mux.HandleFunc("POST /api/v1/ingest", s.ingest)
	s.mux.HandleFunc("GET /api/v1/wifi/keys", s.wifiKeys)
	s.mux.HandleFunc("GET /api/v1/version", s.version)
	s.mux.HandleFunc("GET /healthz", s.version)
	read := func(p string, h http.HandlerFunc) { s.mux.Handle("GET "+p, s.requireRead(h)) }
	read("/api/v1/summary", s.summary)
	read("/api/v1/devices", s.devices)
	read("/api/v1/flows", s.flows)
	read("/api/v1/dns", s.dns)
	read("/api/v1/facts", s.facts)
	read("/api/v1/timeseries", s.timeseries)
	read("/api/v1/graph", s.graph)
	read("/api/v1/entity", s.entity)
	read("/api/v1/sensors", s.sensors)
	read("/api/v1/wifi", s.wifi)
	read("/api/v1/live", s.live)
	s.mux.HandleFunc("GET /", s.web)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.mux.ServeHTTP(w, r)
}

func tokenOK(r *http.Request, want string) bool {
	if want == "" {
		return true
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if got == r.Header.Get("Authorization") {
		got = ""
	}
	if got == "" {
		// EventSource cannot set headers; the live feed takes the token
		// as a parameter.
		got = r.URL.Query().Get("token")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (s *Server) requireRead(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !tokenOK(r, s.cfg.ReadToken) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="netgraph"`)
			httpError(w, http.StatusUnauthorized, errors.New("missing or wrong read token"))
			return
		}
		h(w, r)
	})
}

func httpError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	if err := enc.Encode(v); err != nil {
		slog.Debug("write response", "err", err)
	}
}

func (s *Server) version(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"version": buildinfo.Version, "commit": buildinfo.Commit})
}

func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	if !tokenOK(r, s.cfg.IngestToken) {
		httpError(w, http.StatusUnauthorized, errors.New("missing or wrong ingest token"))
		return
	}
	if v := r.Header.Get(wire.HeaderVersion); v != "" && v != strconv.Itoa(wire.Version) {
		httpError(w, http.StatusBadRequest, fmt.Errorf("unsupported event schema version %s", v))
		return
	}
	sensor := r.Header.Get(wire.HeaderSensor)
	if sensor == "" {
		httpError(w, http.StatusBadRequest, fmt.Errorf("missing %s header", wire.HeaderSensor))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBatch))
	if err != nil {
		httpError(w, http.StatusRequestEntityTooLarge, err)
		return
	}
	var events []wire.Event
	switch r.Header.Get("Content-Encoding") {
	case wire.Encoding:
		events, err = wire.Decode(body)
	case "", "identity":
		events, err = wire.DecodeJSONL(bytes.NewReader(body))
	default:
		err = fmt.Errorf("unsupported Content-Encoding %q", r.Header.Get("Content-Encoding"))
	}
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	res, err := s.cfg.Store.Ingest(r.Context(), sensor, r.Header.Get(wire.HeaderBoot), events)
	if err != nil {
		s.log.Error("ingest", "sensor", sensor, "events", len(events), "err", err)
		httpError(w, http.StatusInternalServerError, errors.New("ingest failed"))
		return
	}
	s.log.Debug("ingested", "sensor", sensor, "accepted", res.Accepted, "duplicates", res.Duplicates)
	writeJSON(w, map[string]int{"accepted": res.Accepted, "duplicates": res.Duplicates})
}

func (s *Server) filter(w http.ResponseWriter, r *http.Request) (model.Filter, bool) {
	f, err := model.ParseFilter(r.URL.Query(), time.Now())
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return f, false
	}
	if !f.From.IsZero() && !f.To.IsZero() && !f.From.Before(f.To) {
		httpError(w, http.StatusBadRequest, errors.New("from must be before to"))
		return f, false
	}
	return f, true
}

func answer[T any](s *Server, w http.ResponseWriter, r *http.Request, q func(context.Context, model.Filter) (T, error)) {
	f, ok := s.filter(w, r)
	if !ok {
		return
	}
	v, err := q(r.Context(), f)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, v)
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		httpError(w, http.StatusNotFound, err)
		return
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	s.log.Error("query", "err", err)
	httpError(w, http.StatusInternalServerError, err)
}

func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	answer(s, w, r, s.cfg.Store.Summary)
}
func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	answer(s, w, r, s.cfg.Store.Devices)
}
func (s *Server) flows(w http.ResponseWriter, r *http.Request) { answer(s, w, r, s.cfg.Store.Flows) }
func (s *Server) dns(w http.ResponseWriter, r *http.Request)   { answer(s, w, r, s.cfg.Store.DNS) }
func (s *Server) facts(w http.ResponseWriter, r *http.Request) { answer(s, w, r, s.cfg.Store.Facts) }

func (s *Server) sensors(w http.ResponseWriter, r *http.Request) {
	v, err := s.cfg.Store.Sensors(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, v)
}

func (s *Server) wifi(w http.ResponseWriter, r *http.Request) {
	answer(s, w, r, s.cfg.Store.WiFi)
}

// wifiKeys hands a sensor what it needs to decrypt Wi-Fi: the PMKs and WEP
// keys from the server's key file, and the stored handshake nonces so it can
// re-derive pairwise keys after a restart, or learn keys another sensor
// found. It is authorised with the ingest token (the sensor's own
// credential), and keys are never served without one.
func (s *Server) wifiKeys(w http.ResponseWriter, r *http.Request) {
	if !tokenOK(r, s.cfg.IngestToken) {
		httpError(w, http.StatusUnauthorized, errors.New("missing or wrong ingest token"))
		return
	}
	hs, err := s.cfg.Store.WiFiHandshakes(r.Context())
	if err != nil {
		httpError(w, http.StatusInternalServerError, errors.New("query failed"))
		return
	}
	out := wire.WiFiKeys{PMKs: []wire.WiFiPMK{}, WEP: []wire.WiFiWEP{}, Handshakes: hs}
	if sec := s.cfg.WiFi; sec != nil && s.cfg.IngestToken != "" {
		for ssid, pmk := range sec.PMKs {
			out.PMKs = append(out.PMKs, wire.WiFiPMK{SSID: ssid, PMK: hex.EncodeToString(pmk)})
		}
		slices.SortFunc(out.PMKs, func(a, b wire.WiFiPMK) int { return cmp.Compare(a.SSID, b.SSID) })
		for i, k := range sec.WEP {
			if k != nil {
				out.WEP = append(out.WEP, wire.WiFiWEP{Index: i, Key: hex.EncodeToString(k)})
			}
		}
	}
	writeJSON(w, out)
}

func (s *Server) timeseries(w http.ResponseWriter, r *http.Request) {
	var step time.Duration
	if v := r.URL.Query().Get("step"); v != "" {
		d, err := model.ParseDuration(v)
		if err != nil {
			httpError(w, http.StatusBadRequest, fmt.Errorf("step: %w", err))
			return
		}
		step = d
	}
	answer(s, w, r, func(ctx context.Context, f model.Filter) (*model.Timeseries, error) {
		return s.cfg.Store.Timeseries(ctx, f, step)
	})
}

func (s *Server) entity(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	answer(s, w, r, func(ctx context.Context, f model.Filter) (*model.EntityDetail, error) {
		return s.cfg.Store.Entity(ctx, id, f)
	})
}

func (s *Server) graph(w http.ResponseWriter, r *http.Request) {
	f, ok := s.filter(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	g, err := s.cfg.Store.Graph(r.Context(), f, model.ParseGraphOptions(q))
	if err != nil {
		s.fail(w, err)
		return
	}
	theme := q.Get("theme")
	switch q.Get("format") {
	case "", "json":
		writeJSON(w, g)
	case "d2":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, graph.RenderD2(g, graph.RenderOptions{Theme: theme}))
	case "svg":
		svg, err := d2render.SVG(g, d2render.Options{Theme: theme, Layout: q.Get("layout")})
		if err != nil {
			s.fail(w, err)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write(svg)
	case "txt", "text":
		txt, err := d2render.Text(g, d2render.Options{Unicode: q.Get("unicode") != "0", Layout: q.Get("layout")})
		if err != nil {
			s.fail(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, txt)
	default:
		httpError(w, http.StatusBadRequest, fmt.Errorf("unknown format %q (json, d2, svg, txt)", q.Get("format")))
	}
}

// live streams ingested events as server-sent events.
func (s *Server) live(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		httpError(w, http.StatusInternalServerError, errors.New("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	ch, cancel := s.cfg.Store.Subscribe()
	defer cancel()
	io.WriteString(w, ": netgraph live\n\n")
	fl.Flush()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			io.WriteString(w, ": ping\n\n")
		case evs := <-ch:
			b, _ := json.Marshal(evs)
			fmt.Fprintf(w, "event: ingest\ndata: %s\n\n", b)
		}
		fl.Flush()
	}
}

const noWebPage = `<!doctype html><meta charset="utf-8"><title>netgraph</title>
<style>body{font:15px system-ui;margin:3rem auto;max-width:40rem;color:#222;background:#fff}code{background:#eee;padding:.1em .3em}</style>
<h1>netgraph</h1><p>This build has no web UI embedded. Build it with <code>make web.build</code> and
<code>-tags embed_web</code>, or run <code>netgraph serve -web-dir web/dist</code>. The API is at <code>/api/v1/</code>.</p>`

func (s *Server) web(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Web == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, noWebPage)
		return
	}
	p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if p == "" {
		p = "index.html"
	}
	// web.wasm ships only gzipped (a quarter of the size, and the binary
	// embeds it): sent as-is to browsers that accept gzip, which is all of
	// them, and inflated here for anything that does not.
	if strings.HasSuffix(p, ".wasm") {
		w.Header().Set("Content-Type", "application/wasm")
		w.Header().Set("Vary", "Accept-Encoding")
		if f, err := s.cfg.Web.Open(p + ".gz"); err == nil {
			defer f.Close()
			if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				w.Header().Set("Content-Encoding", "gzip")
				io.Copy(w, f)
				return
			}
			if zr, err := gzip.NewReader(f); err == nil {
				io.Copy(w, zr)
				return
			}
		}
	}
	if _, err := fs.Stat(s.cfg.Web, p); err != nil {
		p = "index.html" // client-side routes
	}
	if p == "index.html" {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeFileFS(w, r, s.cfg.Web, p)
}
