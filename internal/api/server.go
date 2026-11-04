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
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/netgraph/internal/alert"
	"github.com/xen0bit/netgraph/internal/buildinfo"
	"github.com/xen0bit/netgraph/internal/graph"
	"github.com/xen0bit/netgraph/internal/graph/d2render"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/policy"
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
	// Alerts reports the new-device notifier's counters for /metrics;
	// nil when alerts are off.
	Alerts func() alert.Stats
	// MaxBatch bounds an ingest request body (compressed); default 32 MiB.
	MaxBatch int64
}

// Server serves the API.
type Server struct {
	cfg  Config
	mux  *http.ServeMux
	log  *slog.Logger
	keys atomic.Pointer[wifi.Secrets]

	ingestTok   atomic.Pointer[string]
	readTok     atomic.Pointer[string]
	ingestStats ingestMetrics
	liveSubs    atomic.Int32
	done        chan struct{}
	doneOnce    sync.Once
}

// SetTokens replaces the ingest and read tokens, so a SIGHUP can rotate
// credentials without restarting the server.
func (s *Server) SetTokens(ingest, read string) {
	s.ingestTok.Store(&ingest)
	s.readTok.Store(&read)
}

func (s *Server) ingestToken() string {
	if p := s.ingestTok.Load(); p != nil {
		return *p
	}
	return ""
}

func (s *Server) readToken() string {
	if p := s.readTok.Load(); p != nil {
		return *p
	}
	return ""
}

// Tokens returns the current credentials, for a SIGHUP reload to update one
// without changing the other.
func (s *Server) Tokens() (ingest, read string) { return s.ingestToken(), s.readToken() }

// SetWiFi replaces the Wi-Fi keys served to sensors, such as after the key
// file is reloaded. Sensors pick them up on their next sync.
func (s *Server) SetWiFi(sec *wifi.Secrets) { s.keys.Store(sec) }

// Shutdown ends long-lived streams. http.Server.Shutdown only closes idle
// connections, so without this an open SSE response keeps the server from
// finishing a graceful stop until the shutdown deadline.
func (s *Server) Shutdown() { s.doneOnce.Do(func() { close(s.done) }) }

// New returns a Server.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = 32 << 20
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux(), log: cfg.Logger, done: make(chan struct{})}
	s.SetTokens(cfg.IngestToken, cfg.ReadToken)
	s.keys.Store(cfg.WiFi)
	s.mux.HandleFunc("POST /api/v1/ingest", s.ingest)
	s.mux.HandleFunc("GET /api/v1/wifi/keys", s.wifiKeys)
	s.mux.HandleFunc("GET /api/v1/version", s.version)
	s.mux.HandleFunc("GET /healthz", s.version)
	read := func(p string, h http.HandlerFunc) { s.mux.Handle("GET "+p, s.requireRead(h)) }
	read("/api/v1/summary", s.summary)
	read("/api/v1/devices", s.devices)
	read("/api/v1/flows", s.flows)
	read("/api/v1/destinations", s.destinations)
	read("/api/v1/dns", s.dns)
	read("/api/v1/facts", s.facts)
	read("/api/v1/timeseries", s.timeseries)
	read("/api/v1/graph", s.graph)
	read("/api/v1/entity", s.entity)
	read("/api/v1/sensors", s.sensors)
	read("/api/v1/wifi", s.wifi)
	read("/api/v1/anomalies", s.anomalies)
	read("/api/v1/anomalies/mutes", s.anomalyMutes)
	read("/api/v1/search", s.search)
	read("/api/v1/frame", s.frame)
	read("/api/v1/timeline", s.timeline)
	read("/api/v1/story", s.story)
	read("/api/v1/diff", s.diff)
	read("/api/v1/autopsy", s.autopsyPreview)
	read("/api/v1/incidents", s.incidents)
	read("/api/v1/incidents/{id}", s.incident)
	read("/api/v1/incidents/{id}/autopsy", s.incidentAutopsy)
	read("/api/v1/incidents/{id}/export", s.exportIncident)
	read("/api/v1/export", s.export)
	s.mux.Handle("GET /api/v1/live", s.requireLive(http.HandlerFunc(s.live)))
	read("/metrics", s.metrics)
	s.mux.Handle("PUT /api/v1/devices/{mac}/label", s.requireRead(http.HandlerFunc(s.setLabel)))
	s.mux.Handle("POST /api/v1/anomalies/mute", s.requireRead(http.HandlerFunc(s.muteAnomaly)))
	s.mux.Handle("POST /api/v1/whatif", s.requireRead(http.HandlerFunc(s.whatif)))
	s.mux.Handle("POST /api/v1/ask", s.requireRead(http.HandlerFunc(s.ask)))
	s.mux.Handle("POST /api/v1/incidents", s.requireRead(http.HandlerFunc(s.createIncident)))
	s.mux.Handle("PATCH /api/v1/incidents/{id}", s.requireRead(http.HandlerFunc(s.updateIncident)))
	s.mux.Handle("DELETE /api/v1/incidents/{id}", s.requireRead(http.HandlerFunc(s.deleteIncident)))
	s.mux.Handle("POST /api/v1/incidents/{id}/pin", s.requireRead(http.HandlerFunc(s.pinEvidence)))
	s.mux.Handle("DELETE /api/v1/anomalies/mute", s.requireRead(http.HandlerFunc(s.unmuteAnomaly)))
	s.mux.HandleFunc("GET /", s.web)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'wasm-unsafe-eval' 'unsafe-eval'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
	if r.Method == http.MethodHead && (r.URL.Path == "/api/v1/live" || r.URL.Path == "/api/v1/export") {
		w.Header().Set("Allow", "GET")
		httpError(w, http.StatusMethodNotAllowed, errors.New("HEAD is not supported for this endpoint"))
		return
	}
	if r.URL.Path == "/api/v1/live" || !acceptsGzip(r) {
		s.mux.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Vary", "Accept-Encoding")
	gz := &gzipResponseWriter{ResponseWriter: w, head: r.Method == http.MethodHead}
	defer gz.Close()
	s.mux.ServeHTTP(gz, r)
}

func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		fields := strings.Split(part, ";")
		if strings.TrimSpace(fields[0]) != "gzip" {
			continue
		}
		for _, q := range fields[1:] {
			q = strings.TrimSpace(q)
			if strings.HasPrefix(q, "q=") && strings.TrimPrefix(q, "q=") == "0" {
				return false
			}
		}
		return true
	}
	return false
}

// gzipResponseWriter compresses ordinary responses, but not SSE, HEAD or a
// representation that already has a Content-Encoding (the web WASM asset is
// stored gzipped).
type gzipResponseWriter struct {
	http.ResponseWriter
	gz      *gzip.Writer
	wrote   bool
	encoded bool
	skip    bool
	head    bool
}

// Unwrap lets http.ResponseController reach the connection.
func (g *gzipResponseWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

func (g *gzipResponseWriter) WriteHeader(code int) {
	if g.wrote {
		return
	}
	g.wrote = true
	h := g.Header()
	ct := h.Get("Content-Type")
	g.skip = g.head || code == http.StatusNoContent || code == http.StatusNotModified ||
		h.Get("Content-Encoding") != "" || strings.HasPrefix(ct, "text/event-stream")
	if !g.skip {
		h.Set("Content-Encoding", "gzip")
		h.Del("Content-Length")
		g.encoded = true
		g.gz = gzip.NewWriter(g.ResponseWriter)
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipResponseWriter) Write(p []byte) (int, error) {
	if !g.wrote {
		g.WriteHeader(http.StatusOK)
	}
	if g.encoded {
		return g.gz.Write(p)
	}
	return g.ResponseWriter.Write(p)
}

func (g *gzipResponseWriter) Flush() {
	if g.gz != nil {
		_ = g.gz.Flush()
	}
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (g *gzipResponseWriter) Close() error {
	if g.gz != nil {
		return g.gz.Close()
	}
	return nil
}

func tokenOK(r *http.Request, want string) bool {
	return tokenOKQuery(r, want, false)
}

// tokenOKQuery checks the bearer header and, when allowQuery is true, the
// token parameter EventSource needs. Query tokens leak into access logs and
// Referer headers, so only the live stream accepts one.
func tokenOKQuery(r *http.Request, want string, allowQuery bool) bool {
	if want == "" {
		return true
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if got == r.Header.Get("Authorization") {
		got = ""
	}
	if got == "" && allowQuery {
		got = r.URL.Query().Get("token")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (s *Server) requireRead(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !tokenOK(r, s.readToken()) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="netgraph"`)
			httpError(w, http.StatusUnauthorized, errors.New("missing or wrong read token"))
			return
		}
		h(w, r)
	})
}

func (s *Server) requireLive(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !tokenOKQuery(r, s.readToken(), true) {
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
	if !tokenOK(r, s.ingestToken()) {
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
	// ReadTimeout is deliberately off at the server: a valid 32 MiB batch
	// from a slow sensor may take longer than a browser request. Give the
	// body a generous per-request deadline instead.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(5 * time.Minute))
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
		status := http.StatusBadRequest
		if errors.Is(err, wire.ErrBatchTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		httpError(w, status, err)
		return
	}
	start := time.Now()
	res, err := s.cfg.Store.Ingest(r.Context(), sensor, r.Header.Get(wire.HeaderBoot), events)
	if err != nil {
		s.ingestStats.errors.Add(1)
		s.log.Error("ingest", "sensor", sensor, "events", len(events), "err", err)
		httpError(w, http.StatusInternalServerError, errors.New("ingest failed"))
		return
	}
	s.ingestStats.observe(res.Accepted, res.Duplicates, time.Since(start))
	s.log.Debug("ingested", "sensor", sensor, "accepted", res.Accepted, "duplicates", res.Duplicates)
	writeJSON(w, map[string]int{"accepted": res.Accepted, "duplicates": res.Duplicates})
}

func (s *Server) filter(w http.ResponseWriter, r *http.Request) (model.Filter, bool) {
	now := time.Now()
	f, err := model.ParseFilter(r.URL.Query(), now)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return f, false
	}
	// Resolve the defaults here, not just in the store: a lone future
	// "from" or a "to" before the implied start of the window must be a
	// 400, not an empty or inverted window.
	if f.To.IsZero() {
		f.To = now
	}
	if f.From.IsZero() {
		f.From = f.To.Add(-time.Hour)
	}
	if !f.From.Before(f.To) {
		httpError(w, http.StatusBadRequest, errors.New("from must be before to"))
		return f, false
	}
	if f.Limit < 0 {
		f.Limit = 0
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
	if errors.Is(err, store.ErrInvalid) {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	s.log.Error("query", "err", err)
	httpError(w, http.StatusInternalServerError, errors.New("query failed"))
}

func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	answer(s, w, r, s.cfg.Store.Summary)
}
func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	answer(s, w, r, s.cfg.Store.Devices)
}
func (s *Server) flows(w http.ResponseWriter, r *http.Request) { answer(s, w, r, s.cfg.Store.Flows) }
func (s *Server) destinations(w http.ResponseWriter, r *http.Request) {
	f, ok := s.filter(w, r)
	if !ok {
		return
	}
	ds, err := s.cfg.Store.Destinations(r.Context(), f)
	if err != nil {
		s.fail(w, err)
		return
	}
	if r.URL.Query().Get("group") == "site" {
		ds = groupDestinations(ds)
	}
	writeJSON(w, ds)
}

// groupDestinations folds names under their registrable site for the
// Destinations view. Addresses stay addresses: an address has no site.
func groupDestinations(ds []model.Destination) []model.Destination {
	by := map[string]*model.Destination{}
	for _, d := range ds {
		key, kind := d.Key, d.Kind
		if kind != "ip" {
			if site := graph.Site(d.Key); site != "" {
				key = site
			}
		}
		p := by[key]
		if p == nil {
			copy := d
			copy.Key, copy.Label, copy.Kind = key, key, kind
			if kind != "ip" {
				copy.Kind = "name"
			}
			by[key] = &copy
			continue
		}
		p.Connections += d.Connections
		// Devices cannot be de-duplicated after aggregation; max is a
		// lower bound, whereas summing would claim more than exist.
		p.Devices = max(p.Devices, d.Devices)
		p.BytesOut += d.BytesOut
		p.BytesIn += d.BytesIn
		if d.FirstSeen > 0 && (p.FirstSeen == 0 || d.FirstSeen < p.FirstSeen) {
			p.FirstSeen = d.FirstSeen
		}
		p.LastSeen = max(p.LastSeen, d.LastSeen)
		p.Ports = unionStrings(p.Ports, d.Ports)
		p.RemoteIPs = unionStrings(p.RemoteIPs, d.RemoteIPs)
	}
	out := make([]model.Destination, 0, len(by))
	for _, d := range by {
		out = append(out, *d)
	}
	slices.SortFunc(out, func(a, b model.Destination) int {
		if a.BytesOut+a.BytesIn != b.BytesOut+b.BytesIn {
			if a.BytesOut+a.BytesIn > b.BytesOut+b.BytesIn {
				return -1
			}
			return 1
		}
		return cmp.Compare(a.Key, b.Key)
	})
	return out
}

func unionStrings(a, b []string) []string {
	seen := map[string]bool{}
	out := append([]string(nil), a...)
	for _, s := range out {
		seen[s] = true
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}
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

func (s *Server) anomalies(w http.ResponseWriter, r *http.Request) {
	answer(s, w, r, s.cfg.Store.Anomalies)
}

// wifiKeys hands a sensor what it needs to decrypt Wi-Fi: the PMKs and WEP
// keys from the server's key file, and the stored handshake nonces and
// wrapped group keys so it can re-derive pairwise and group keys after a
// restart, or learn keys another sensor found. It is authorised with the ingest token (the sensor's own
// credential), and keys are never served without one.
func (s *Server) wifiKeys(w http.ResponseWriter, r *http.Request) {
	if s.ingestToken() == "" {
		// With -no-auth this endpoint has no credential to check, so it
		// must not hand out even the non-secret handshake/group-key sync
		// records. Sensors need an ingest token to sync Wi-Fi keys.
		httpError(w, http.StatusForbidden, errors.New("wifi keys require an ingest token"))
		return
	}
	if !tokenOK(r, s.ingestToken()) {
		httpError(w, http.StatusUnauthorized, errors.New("missing or wrong ingest token"))
		return
	}
	var since int64
	if raw := r.URL.Query().Get("since"); raw != "" {
		v, perr := strconv.ParseInt(raw, 10, 64)
		if perr != nil || v < 0 {
			httpError(w, http.StatusBadRequest, errors.New("since must be a non-negative unix millisecond timestamp"))
			return
		}
		since = v
	}
	hs, err := s.cfg.Store.WiFiHandshakesSince(r.Context(), since)
	if err != nil {
		httpError(w, http.StatusInternalServerError, errors.New("query failed"))
		return
	}
	gks, err := s.cfg.Store.WiFiGroupKeysSince(r.Context(), since)
	if err != nil {
		httpError(w, http.StatusInternalServerError, errors.New("query failed"))
		return
	}
	out := wire.WiFiKeys{PMKs: []wire.WiFiPMK{}, WEP: []wire.WiFiWEP{}, Handshakes: hs, GroupKeys: gks}
	if sec := s.keys.Load(); sec != nil && s.ingestToken() != "" {
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

// anomalyMutes lists the mutes in force.
func (s *Server) anomalyMutes(w http.ResponseWriter, r *http.Request) {
	m, err := s.cfg.Store.AnomalyMutes(r.Context(), true)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"mutes": m})
}

// muteAnomaly creates or replaces a mute. Like setLabel it requires a JSON
// body, so a cross-origin form cannot post one without a preflight.
func (s *Server) muteAnomaly(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		httpError(w, http.StatusUnsupportedMediaType, errors.New("expected application/json"))
		return
	}
	var body model.AnomalyMute
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.cfg.Store.SetAnomalyMute(r.Context(), body); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// unmuteAnomaly removes one mute. DELETE is never a simple cross-origin
// request, so it needs no body check.
func (s *Server) unmuteAnomaly(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if err := s.cfg.Store.DeleteAnomalyMute(r.Context(), q.Get("kind"), q.Get("device"), q.Get("entity")); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// setLabel names a device by hand ({"label": ""} clears the name). It is
// authorised like the UI that calls it, with the read token. A JSON body is
// required, so a cross-origin page cannot send it without a CORS preflight,
// which this server never grants.
func (s *Server) setLabel(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		httpError(w, http.StatusUnsupportedMediaType, errors.New("expected application/json"))
		return
	}
	var body struct {
		Label *string `json:"label"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body.Label == nil {
		httpError(w, http.StatusBadRequest, errors.New(`expected {"label": "..."}`))
		return
	}
	if err := s.cfg.Store.SetDeviceLabel(r.Context(), r.PathValue("mac"), *body.Label); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	n, _ := strconv.Atoi(q.Get("limit"))
	res, err := s.cfg.Store.Search(r.Context(), q.Get("q"), n)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, res)
}

func parseLookback(q map[string][]string, def time.Duration) (time.Duration, error) {
	raw := ""
	if v, ok := q["lookback"]; ok && len(v) > 0 {
		raw = v[0]
	}
	if raw == "" {
		return def, nil
	}
	d, err := model.ParseDuration(raw)
	if err != nil || d <= 0 || d > 90*24*time.Hour {
		return 0, fmt.Errorf("lookback must be a positive duration up to 90d")
	}
	return d, nil
}

func (s *Server) frame(w http.ResponseWriter, r *http.Request) {
	f, ok := s.filter(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	lb := 5 * time.Minute
	if q.Get("lookback") != "" {
		var err error
		lb, err = parseLookback(r.URL.Query(), lb)
		if err != nil {
			httpError(w, http.StatusBadRequest, err)
			return
		}
	} else if q.Get("from") != "" || q.Get("to") != "" {
		if d := f.To.Sub(f.From); d > 0 && d <= 90*24*time.Hour {
			lb = d
		}
	}
	if raw := q.Get("at"); raw != "" {
		t, err := model.ParseTime(raw, s.cfg.Store.Now())
		if err != nil {
			httpError(w, http.StatusBadRequest, err)
			return
		}
		f.To, f.From = t, t.Add(-lb)
	} else if f.To.Sub(f.From) > 0 {
		f.From = f.To.Add(-lb)
	}
	scope := q.Get("scope")
	if scope != "" {
		kind, key, _ := strings.Cut(scope, ":")
		switch kind {
		case "device":
			f.Device = key
		case "domain":
			f.DomainExact = key
		case "ip":
			f.IP = key
		default:
			httpError(w, http.StatusBadRequest, fmt.Errorf("unknown scope %q", scope))
			return
		}
	}
	if q.Get("limit") == "" {
		f.Limit = 1000
	}
	out, err := s.cfg.Store.Frame(r.Context(), f)
	if err != nil {
		s.fail(w, err)
		return
	}
	out.Scope = scope
	writeJSON(w, out)
}

func (s *Server) timeline(w http.ResponseWriter, r *http.Request) {
	f, ok := s.filter(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit := 500
	if raw := q.Get("limit"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 {
			httpError(w, http.StatusBadRequest, errors.New("limit must be a positive integer"))
			return
		}
		limit = min(v, 5000)
	}
	kinds := []string{}
	for _, k := range strings.Split(q.Get("kinds"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			kinds = append(kinds, k)
		}
	}
	page, err := s.cfg.Store.Timeline(r.Context(), f, model.TimelineQuery{
		Entity: q.Get("entity"), Kinds: kinds, Cursor: q.Get("cursor"), Limit: limit,
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, page)
}

func (s *Server) story(w http.ResponseWriter, r *http.Request) {
	f, ok := s.filter(w, r)
	if !ok {
		return
	}
	id := r.URL.Query().Get("entity")
	if id == "" {
		httpError(w, http.StatusBadRequest, errors.New("entity is required"))
		return
	}
	out, err := s.cfg.Store.Story(r.Context(), id, f)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) diff(w http.ResponseWriter, r *http.Request) {
	f, ok := s.filter(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	lb, err := parseLookback(q, 5*time.Minute)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	parse := func(name string) (time.Time, bool, error) {
		raw := q.Get(name)
		if raw == "" {
			return time.Time{}, false, nil
		}
		t, err := model.ParseTime(raw, s.cfg.Store.Now())
		return t, true, err
	}
	aTo, aSet, err := parse("at_a")
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	bTo, bSet, err := parse("at_b")
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if !aSet && !bSet {
		aTo, bTo = f.From, f.To
		aSet, bSet = true, true
	}
	if !aSet {
		aTo = bTo
	}
	if !bSet {
		bTo = aTo
	}
	fa, fb := f, f
	fa.To, fa.From = aTo, aTo.Add(-lb)
	fb.To, fb.From = bTo, bTo.Add(-lb)
	out, err := s.cfg.Store.Diff(r.Context(), fa, fb, q.Get("scope"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func parseIncidentID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("incident id must be a positive integer")
	}
	return id, nil
}

func (s *Server) ask(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Q    string `json:"q"`
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	now := s.cfg.Store.Now()
	f, err := model.ParseFilter(r.URL.Query(), now)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if in.From != "" {
		if f.From, err = model.ParseTime(in.From, now); err != nil {
			httpError(w, http.StatusBadRequest, err)
			return
		}
	}
	if in.To != "" {
		if f.To, err = model.ParseTime(in.To, now); err != nil {
			httpError(w, http.StatusBadRequest, err)
			return
		}
	}
	if f.To.IsZero() {
		f.To = now
	}
	if f.From.IsZero() {
		f.From = f.To.Add(-24 * time.Hour)
	}
	if !f.From.Before(f.To) {
		httpError(w, http.StatusBadRequest, errors.New("from must be before to"))
		return
	}
	out, err := s.cfg.Store.Ask(r.Context(), in.Q, f)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) whatif(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Policy json.RawMessage "json:\"policy\""
		From   string          "json:\"from\""
		To     string          "json:\"to\""
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	p, err := policy.Parse(bytes.NewReader(in.Policy))
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	now := s.cfg.Store.Now()
	f, err := model.ParseFilter(r.URL.Query(), now)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if in.From != "" {
		if f.From, err = model.ParseTime(in.From, now); err != nil {
			httpError(w, http.StatusBadRequest, err)
			return
		}
	}
	if in.To != "" {
		if f.To, err = model.ParseTime(in.To, now); err != nil {
			httpError(w, http.StatusBadRequest, err)
			return
		}
	}
	if f.To.IsZero() {
		f.To = now
	}
	if f.From.IsZero() {
		f.From = f.To.Add(-7 * 24 * time.Hour)
	}
	if !f.From.Before(f.To) {
		httpError(w, http.StatusBadRequest, errors.New("from must be before to"))
		return
	}
	out, err := s.cfg.Store.WhatIf(r.Context(), p, f, r.URL.Query().Get("scope"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) autopsyPreview(w http.ResponseWriter, r *http.Request) {
	f, ok := s.filter(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	ts := f.To.UnixMilli()
	if raw := q.Get("ts"); raw != "" {
		t, err := model.ParseTime(raw, s.cfg.Store.Now())
		if err != nil {
			httpError(w, http.StatusBadRequest, err)
			return
		}
		ts = t.UnixMilli()
		if q.Get("from") == "" && q.Get("to") == "" {
			f.From, f.To = t.Add(-10*time.Minute), t.Add(10*time.Minute)
		}
	}
	a := model.Anomaly{
		Kind: q.Get("kind"), Severity: q.Get("severity"), TS: ts,
		Device: q.Get("device"), DeviceName: q.Get("device_name"),
		Entity: q.Get("entity"), Summary: q.Get("summary"),
	}
	if a.Kind == "" {
		httpError(w, http.StatusBadRequest, errors.New("kind is required"))
		return
	}
	out, err := s.cfg.Store.Autopsy(r.Context(), a, f)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) incidents(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 || v > 1000 {
			httpError(w, http.StatusBadRequest, errors.New("limit must be 1..1000"))
			return
		}
		limit = v
	}
	out, err := s.cfg.Store.Incidents(r.Context(), r.URL.Query().Get("status"), limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) incident(w http.ResponseWriter, r *http.Request) {
	id, err := parseIncidentID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	out, err := s.cfg.Store.IncidentDetail(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) incidentAutopsy(w http.ResponseWriter, r *http.Request) {
	id, err := parseIncidentID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	out, err := s.cfg.Store.IncidentAutopsy(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) createIncident(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Anomaly model.Anomaly "json:\"anomaly\""
		Title   string        "json:\"title\""
		From    string        "json:\"from\""
		To      string        "json:\"to\""
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if in.Anomaly.Kind == "" {
		httpError(w, http.StatusBadRequest, errors.New("anomaly.kind is required"))
		return
	}
	from, to := time.Time{}, time.Time{}
	if in.From != "" {
		var perr error
		if from, perr = model.ParseTime(in.From, s.cfg.Store.Now()); perr != nil {
			httpError(w, http.StatusBadRequest, perr)
			return
		}
	}
	if in.To != "" {
		var perr error
		if to, perr = model.ParseTime(in.To, s.cfg.Store.Now()); perr != nil {
			httpError(w, http.StatusBadRequest, perr)
			return
		}
	}
	out, err := s.cfg.Store.CreateIncident(r.Context(), in.Anomaly, in.Title, from, to)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) updateIncident(w http.ResponseWriter, r *http.Request) {
	id, err := parseIncidentID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	var in struct {
		Status  string "json:\"status\""
		Title   string "json:\"title\""
		Summary string "json:\"summary\""
		Note    string "json:\"note\""
		Author  string "json:\"author\""
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	out, err := s.cfg.Store.UpdateIncident(r.Context(), id, in.Status, in.Title, in.Summary, in.Note, in.Author)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) deleteIncident(w http.ResponseWriter, r *http.Request) {
	id, err := parseIncidentID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.cfg.Store.DeleteIncident(r.Context(), id); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) pinEvidence(w http.ResponseWriter, r *http.Request) {
	id, err := parseIncidentID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	var in struct {
		Evidence string "json:\"evidence\""
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.cfg.Store.PinEvidence(r.Context(), id, in.Evidence); err != nil {
		s.fail(w, err)
		return
	}
	out, err := s.cfg.Store.IncidentDetail(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) exportIncident(w http.ResponseWriter, r *http.Request) {
	id, err := parseIncidentID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	d, err := s.cfg.Store.IncidentDetail(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	a, err := s.cfg.Store.IncidentAutopsy(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	bundle := map[string]any{
		"schema": "netgraph.incident.v1", "incident": d, "autopsy": a,
		"generated": time.Now().UTC().Format(time.RFC3339),
	}
	b, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=netgraph-incident-%d.json", id))
	_, _ = w.Write(b)
}

func (s *Server) graph(w http.ResponseWriter, r *http.Request) {
	f, ok := s.filter(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	if r.Method == http.MethodHead {
		switch q.Get("format") {
		case "svg":
			w.Header().Set("Content-Type", "image/svg+xml")
		case "d2", "txt", "text":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		default:
			w.Header().Set("Content-Type", "application/json")
		}
		return
	}
	g, err := s.cfg.Store.Graph(r.Context(), f, model.ParseGraphOptions(q))
	if err != nil {
		s.fail(w, err)
		return
	}
	if layout := q.Get("layout"); layout != "" && layout != "elk" && layout != "dagre" {
		httpError(w, http.StatusBadRequest, fmt.Errorf("layout: %q is not elk or dagre", layout))
		return
	}
	if len(g.Nodes) > 2000 || len(g.Edges) > 5000 {
		httpError(w, http.StatusBadRequest, fmt.Errorf("graph has %d nodes and %d edges; narrow the window or filter it", len(g.Nodes), len(g.Edges)))
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
	select {
	case <-s.done:
		httpError(w, http.StatusServiceUnavailable, errors.New("server is shutting down"))
		return
	default:
	}
	if n := s.liveSubs.Add(1); n > 100 {
		s.liveSubs.Add(-1)
		httpError(w, http.StatusServiceUnavailable, errors.New("too many live listeners"))
		return
	}
	defer s.liveSubs.Add(-1)
	fl, ok := w.(http.Flusher)
	if !ok {
		httpError(w, http.StatusInternalServerError, errors.New("streaming unsupported"))
		return
	}
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	ch, cancel := s.cfg.Store.Subscribe()
	defer cancel()
	io.WriteString(w, ": netgraph live\n\n")
	fl.Flush()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	// Coalesce ingest batches: a busy router can produce several per
	// second, while the UI only schedules one refresh. The data still
	// names the events for a future live view, but is bounded.
	coalesce := time.NewTicker(500 * time.Millisecond)
	defer coalesce.Stop()
	var pending []store.LiveEvent
	for {
		wrote := false
		select {
		case <-r.Context().Done():
			return
		case <-s.done:
			return
		case <-ping.C:
			io.WriteString(w, ": ping\n\n")
			wrote = true
		case evs := <-ch:
			if len(pending) < 2000 {
				pending = append(pending, evs...)
			}
		case <-coalesce.C:
			if len(pending) > 0 {
				b, _ := json.Marshal(pending)
				fmt.Fprintf(w, "event: ingest\ndata: %s\n\n", b)
				pending = pending[:0]
				wrote = true
			}
		}
		if !wrote {
			continue
		}
		_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if err := rc.Flush(); err != nil {
			return
		}
	}
}

const noWebPage = `<!doctype html><meta charset="utf-8"><title>netgraph</title>
<style>body{font:15px system-ui;margin:3rem auto;max-width:40rem;color:#222;background:#fff}code{background:#eee;padding:.1em .3em}</style>
<h1>netgraph</h1><p>This build has no web UI embedded. Build it with <code>make web.build</code> and
<code>-tags embed_web</code>, or run <code>netgraph serve -web-dir web/dist</code>. The API is at <code>/api/v1/</code>.</p>`

func (s *Server) web(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
		httpError(w, http.StatusNotFound, errors.New("unknown API endpoint"))
		return
	}
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
		w.Header().Set("Cache-Control", "no-cache")
		if f, err := s.cfg.Web.Open(p + ".gz"); err == nil {
			defer f.Close()
			if st, serr := f.Stat(); serr == nil && acceptsGzip(r) {
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
				io.Copy(w, f)
				return
			}
			if zr, zerr := gzip.NewReader(f); zerr == nil {
				defer zr.Close()
				io.Copy(w, zr)
				return
			}
			httpError(w, http.StatusInternalServerError, errors.New("web UI asset is corrupt"))
			return
		}
	}
	st, err := fs.Stat(s.cfg.Web, p)
	if err != nil || st.IsDir() {
		p = "index.html" // client-side routes, never a directory listing
	}
	if p == "index.html" || strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".css") {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeFileFS(w, r, s.cfg.Web, p)
}
