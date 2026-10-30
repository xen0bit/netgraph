package wire

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Emitter is where a sensor's events go. Emit must not block for long: it is
// called from the capture path.
type Emitter interface {
	Emit(Event)
}

// ShipperConfig configures a Shipper.
type ShipperConfig struct {
	URL       string // server base URL; batches go to URL + "/api/v1/ingest"
	Token     string
	Sensor    string
	TLSConfig *tls.Config

	MaxEvents     int           // seal a batch at this many events (default 2000)
	FlushInterval time.Duration // seal a non-empty batch at least this often (default 2s)
	SpoolBytes    int           // bound on compressed batches held for retry (default 32 MiB)
	Logger        *slog.Logger
}

// Shipper batches events, compresses each batch once, holds sealed batches in
// a bounded spool and posts them to the server in order, retrying with
// backoff. When the spool is full the oldest batch is dropped and counted:
// on a router, losing old data beats running out of memory.
type Shipper struct {
	cfg    ShipperConfig
	boot   string
	client *http.Client
	log    *slog.Logger

	mu         sync.Mutex
	sealMu     sync.Mutex // keeps sealed batches in sequence order
	sendMu     sync.Mutex // one sender at a time (Run and an explicit Flush)
	seq        uint64
	pending    []Event
	spool      []batch
	spoolBytes int
	wake       chan struct{}

	stats ShipperStats
}

// ShipperStats are cumulative counters.
type ShipperStats struct {
	Queued        int
	EventsDropped uint64
	BatchesSent   uint64
	SendErrors    uint64
}

type batch struct {
	first, last uint64
	n           int
	body        []byte
}

// NewShipper returns a Shipper; call Run to start sending.
func NewShipper(cfg ShipperConfig) *Shipper {
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = 2000
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 2 * time.Second
	}
	if cfg.SpoolBytes <= 0 {
		cfg.SpoolBytes = 32 << 20
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg.TLSConfig
	tr.MaxIdleConns = 2
	return &Shipper{
		cfg:    cfg,
		boot:   NewBootID(),
		client: &http.Client{Transport: tr, Timeout: 30 * time.Second},
		log:    cfg.Logger,
		wake:   make(chan struct{}, 1),
	}
}

// NewBootID returns a random identifier for one run of a sensor.
func NewBootID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Boot is this run's boot ID.
func (s *Shipper) Boot() string { return s.boot }

// FetchWiFiKeys pulls the Wi-Fi keys the server holds for its sensors: PMKs
// and WEP keys from its key file, and the stored handshake nonces, so the
// sensor can decrypt without a key file of its own and re-derive pairwise
// keys after a restart or from another sensor's capture.
func (s *Shipper) FetchWiFiKeys(ctx context.Context) (*WiFiKeys, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.URL+"/api/v1/wifi/keys", nil)
	if err != nil {
		return nil, err
	}
	if s.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("fetch wifi keys: %s", resp.Status)
	}
	var out WiFiKeys
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Emit queues an event, assigning its sequence number.
func (s *Shipper) Emit(ev Event) {
	s.mu.Lock()
	s.seq++
	ev.Seq = s.seq
	s.pending = append(s.pending, ev)
	full := len(s.pending) >= s.cfg.MaxEvents
	s.mu.Unlock()
	if full {
		s.seal()
	}
}

// Stats returns a snapshot of the counters.
func (s *Shipper) Stats() ShipperStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.Queued = len(s.pending)
	for _, b := range s.spool {
		st.Queued += b.n
	}
	return st
}

// seal encodes the pending events into a batch on the spool.
func (s *Shipper) seal() {
	// Encoding and appending must stay in one order: two concurrent seals
	// that took pending events A then B must not spool B before A, or the
	// server would skip A as a duplicate of B's higher sequence numbers.
	s.sealMu.Lock()
	defer s.sealMu.Unlock()
	s.mu.Lock()
	events := s.pending
	s.pending = nil
	s.mu.Unlock()
	if len(events) == 0 {
		return
	}
	body, err := Encode(events)
	if err != nil {
		s.log.Error("encode batch", "err", err)
		return
	}
	s.mu.Lock()
	s.spool = append(s.spool, batch{first: events[0].Seq, last: events[len(events)-1].Seq, n: len(events), body: body})
	s.spoolBytes += len(body)
	for s.spoolBytes > s.cfg.SpoolBytes && len(s.spool) > 1 {
		old := s.spool[0]
		s.spool = s.spool[1:]
		s.spoolBytes -= len(old.body)
		s.stats.EventsDropped += uint64(old.n)
		s.log.Warn("spool full, dropped oldest batch", "events", old.n)
	}
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run seals and sends batches until ctx is done, then makes one last attempt
// (bounded by a short timeout) to deliver what is left.
func (s *Shipper) Run(ctx context.Context) {
	tick := time.NewTicker(s.cfg.FlushInterval)
	defer tick.Stop()
	backoff := time.Duration(0)
	for {
		if backoff > 0 {
			select {
			case <-ctx.Done():
				s.drain()
				return
			case <-time.After(backoff):
			}
		}
		select {
		case <-ctx.Done():
			s.drain()
			return
		case <-tick.C:
			s.seal()
		case <-s.wake:
		}
		if err := s.sendAll(ctx); err != nil {
			s.mu.Lock()
			s.stats.SendErrors++
			s.mu.Unlock()
			backoff = nextBackoff(backoff)
			s.log.Warn("send batch", "err", err, "retry_in", backoff)
			continue
		}
		backoff = 0
	}
}

func nextBackoff(d time.Duration) time.Duration {
	if d == 0 {
		return time.Second
	}
	if d *= 2; d > time.Minute {
		d = time.Minute
	}
	return d
}

// Flush seals pending events and tries to send everything spooled.
func (s *Shipper) Flush(ctx context.Context) error {
	s.seal()
	return s.sendAll(ctx)
}

func (s *Shipper) drain() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Flush(ctx); err != nil {
		s.log.Warn("final flush incomplete", "err", err, "events_unsent", s.Stats().Queued)
	}
}

func (s *Shipper) sendAll(ctx context.Context) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	for {
		s.mu.Lock()
		if len(s.spool) == 0 {
			s.mu.Unlock()
			return nil
		}
		b := s.spool[0]
		s.mu.Unlock()
		if err := s.post(ctx, b); err != nil {
			return err
		}
		s.mu.Lock()
		// The head can only have been dropped by seal's overflow handling,
		// which never drops the last batch, so compare before removing.
		if len(s.spool) > 0 && s.spool[0].first == b.first {
			s.spool = s.spool[1:]
			s.spoolBytes -= len(b.body)
		}
		s.stats.BatchesSent++
		s.mu.Unlock()
	}
}

func (s *Shipper) post(ctx context.Context, b batch) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL+"/api/v1/ingest", bytes.NewReader(b.body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("Content-Encoding", Encoding)
	req.Header.Set(HeaderSensor, s.cfg.Sensor)
	req.Header.Set(HeaderBoot, s.boot)
	req.Header.Set(HeaderVersion, strconv.Itoa(Version))
	if s.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	switch {
	case resp.StatusCode/100 == 2:
		return nil
	case resp.StatusCode == http.StatusBadRequest:
		// The server will never accept this batch; retrying it forever would
		// wedge everything behind it.
		s.log.Error("server rejected batch, dropping it", "status", resp.Status, "body", string(msg), "events", b.n)
		s.mu.Lock()
		s.stats.EventsDropped += uint64(b.n)
		s.mu.Unlock()
		return nil
	default:
		return fmt.Errorf("server returned %s: %s", resp.Status, bytes.TrimSpace(msg))
	}
}

// JSONWriter is an Emitter that writes uncompressed JSON lines, for
// `-server -` (stdout) and debugging.
type JSONWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
	seq uint64
}

func NewJSONWriter(w io.Writer) *JSONWriter { return &JSONWriter{enc: json.NewEncoder(w)} }

func (j *JSONWriter) Emit(ev Event) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.seq++
	ev.Seq = j.seq
	_ = j.enc.Encode(&ev)
}
