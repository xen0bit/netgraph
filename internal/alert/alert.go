// Package alert delivers notifications: to a webhook, and to ntfy, Gotify, Telegram
// and email (channels.go).
//
// The webhook's payload is JSON that common receivers understand without glue: Slack
// and Mattermost read "text", Discord reads "content", and anything else can
// use the structured "device" object. Delivery is asynchronous and bounded:
// the ingest path only enqueues, a full queue drops (and logs) rather than
// blocking, and each channel retries a few times with backoff, on its own, so one
// that's down doesn't hold up the others.
package alert

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/store"
)

// Config configures a Notifier.
type Config struct {
	// URL receives a POST per new device.
	URL string
	// Routes are further channels, each with what should reach it.
	Routes []Route
	// Learn suppresses alerts until this long after the network was first
	// seen (Since), so a fresh install does not report every device in the
	// house. Zero alerts from the start.
	Learn time.Duration
	// Since reports when the first sensor first reported, or the zero time
	// if none has yet.
	Since func(context.Context) (time.Time, error)
	// Client posts the webhook (default: 10s timeout).
	Client *http.Client
	// Queue bounds alerts waiting to be posted (default 256).
	Queue  int
	Logger *slog.Logger
	// AnomalyMin is the least severity posted by NotifyAnomaly: low,
	// medium, high. Empty disables anomaly alerts.
	AnomalyMin string
	// AnomalyCooldown suppresses a repeat of the same finding for this
	// long (default 1h).
	AnomalyCooldown time.Duration
	// AnomalyKinds limits alerts to these finding kinds. Empty means all.
	AnomalyKinds []string
}

// Payload is the JSON posted for one new device or anomaly.
type Payload struct {
	Event   string           `json:"event"` // "new_device" or "anomaly"
	Text    string           `json:"text"`
	Content string           `json:"content"`
	Device  *store.NewDevice `json:"device,omitempty"`
	Anomaly *model.Anomaly   `json:"anomaly,omitempty"`
	// AllowedMentions stops Discord from turning text into pings.
	AllowedMentions struct {
		Parse []string `json:"parse"`
	} `json:"allowed_mentions"`
}

type notice struct {
	device  *store.NewDevice
	anomaly *model.Anomaly
	report  string
}

// Notifier delivers alerts. Notify is safe for concurrent use.
type Notifier struct {
	cfg     Config
	log     *slog.Logger
	queue   chan notice
	backoff time.Duration // first retry delay; tests shorten it

	mu       sync.Mutex
	cooldown map[string]time.Time // anomaly key -> last posted

	routes []*routeWorker
	now    func() time.Time // tests

	sent, failed, dropped, learning atomic.Uint64
}

// Stats counts alerts by outcome, for /metrics.
type Stats struct {
	Sent, Failed, Dropped, Learning uint64
}

// Stats returns the counters.
func (n *Notifier) Stats() Stats {
	return Stats{Sent: n.sent.Load(), Failed: n.failed.Load(), Dropped: n.dropped.Load(), Learning: n.learning.Load()}
}

// New returns a Notifier; call Run to deliver.
func New(cfg Config) *Notifier {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Queue <= 0 {
		cfg.Queue = 256
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.AnomalyCooldown <= 0 {
		cfg.AnomalyCooldown = time.Hour
	}
	n := &Notifier{cfg: cfg, log: cfg.Logger, queue: make(chan notice, cfg.Queue),
		cooldown: map[string]time.Time{}, backoff: time.Second, now: time.Now}
	routes := cfg.Routes
	if cfg.URL != "" {
		routes = append([]Route{{Channel: &webhookChannel{url: cfg.URL, client: cfg.Client, name: "webhook"}}}, routes...)
	}
	for _, r := range routes {
		n.routes = append(n.routes, &routeWorker{Route: r, n: n, in: make(chan work, cfg.Queue)})
	}
	return n
}

// work is one message for one route. urgent goes through quiet hours.
type work struct {
	p      Payload
	what   string
	detail string
	urgent bool
}

// routeWorker delivers to one channel, so a dead one holds up only itself.
type routeWorker struct {
	Route
	n       *Notifier
	in      chan work
	held    []Payload
	dropped int
}

func (w *routeWorker) run(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case m := <-w.in:
			if w.Quiet != nil && !m.urgent && w.Quiet.In(w.n.now()) {
				if len(w.held) < maxHeld {
					w.held = append(w.held, m.p)
				} else {
					w.dropped++
				}
				continue
			}
			w.flush(ctx)
			w.n.deliver(ctx, w.Channel, m.p, m.what, m.detail)
		case <-tick.C:
			w.flush(ctx)
		}
	}
}

// flush sends what piled up, once quiet hours are over.
func (w *routeWorker) flush(ctx context.Context) {
	if len(w.held) == 0 || (w.Quiet != nil && w.Quiet.In(w.n.now())) {
		return
	}
	p := heldDigest(w.held, w.dropped)
	w.held, w.dropped = nil, 0
	w.n.deliver(ctx, w.Channel, p, "quiet hours digest", "")
}

// dispatch hands a message to every route that wants it.
func (n *Notifier) dispatch(p Payload, a *model.Anomaly, what, detail string) {
	urgent := a != nil && a.Severity == model.SeverityHigh
	for _, w := range n.routes {
		if !w.wants(a) {
			continue
		}
		select {
		case w.in <- work{p, what, detail, urgent}:
		default:
			n.dropped.Add(1)
			n.log.Warn("alert channel queue full; dropping", "channel", w.Name(), "event", what)
		}
	}
}

// ChannelInfo is what a person can be told about a channel: no secrets.
type ChannelInfo struct {
	Name  string   `json:"name"`
	Min   string   `json:"min,omitempty"`
	Kinds []string `json:"kinds,omitempty"`
	Quiet string   `json:"quiet,omitempty"`
}

// Channels lists where alerts go.
func (n *Notifier) Channels() []ChannelInfo {
	out := make([]ChannelInfo, 0, len(n.routes))
	for _, w := range n.routes {
		c := ChannelInfo{Name: w.Name(), Min: w.Min, Kinds: w.Kinds}
		if w.Quiet != nil {
			c.Quiet = w.Quiet.String()
		}
		out = append(out, c)
	}
	return out
}

// Test sends a message straight to a channel, past its filters and quiet hours, and
// says what happened. One attempt: a person is waiting.
func (n *Notifier) Test(ctx context.Context, name string) error {
	for _, w := range n.routes {
		if w.Name() == name {
			return w.Send(ctx, NewReportPayload("A test from netgraph: this channel works."))
		}
	}
	return ErrNoChannel
}

// ErrNoChannel is Test's answer for a name it doesn't know.
var ErrNoChannel = errors.New("no such channel")

// SetSince sets Config.Since, for when the store is opened after the
// notifier is created (the store's callback is the notifier). Call it
// before Run.
func (n *Notifier) SetSince(f func(context.Context) (time.Time, error)) { n.cfg.Since = f }

// Notify enqueues an alert without blocking. It is store.Config.OnNewDevice.
func (n *Notifier) Notify(d store.NewDevice) {
	select {
	case n.queue <- notice{device: &d}:
	default:
		n.dropped.Add(1)
		n.log.Warn("alert queue full; dropping new-device alert", "mac", d.MAC)
	}
}

// NotifyAnomaly enqueues an anomaly finding at or above AnomalyMin, with a
// cooldown per finding so a condition that persists in every window does not
// page once a minute.
// NotifyReport queues a periodic summary. Unlike anomalies it has no
// cooldown: the caller decides the schedule.
func (n *Notifier) NotifyReport(text string) {
	select {
	case n.queue <- notice{report: text}:
	default:
		n.dropped.Add(1)
		n.log.Warn("alert queue full; dropping report")
	}
}

func (n *Notifier) NotifyAnomaly(a model.Anomaly) {
	if n.cfg.AnomalyMin == "" || model.SeverityRank(a.Severity) < model.SeverityRank(n.cfg.AnomalyMin) {
		return
	}
	if len(n.cfg.AnomalyKinds) > 0 && !slices.Contains(n.cfg.AnomalyKinds, a.Kind) {
		return
	}
	key := a.Kind + "|" + a.Device + "|" + a.Entity + "|" + a.Severity
	now := time.Now()
	n.mu.Lock()
	last, ok := n.cooldown[key]
	if ok && now.Sub(last) < n.cfg.AnomalyCooldown {
		n.mu.Unlock()
		return
	}
	n.mu.Unlock()
	select {
	case n.queue <- notice{anomaly: &a}:
		// Commit the cooldown only after the alert is queued: a full
		// queue or a failed delivery must not silence the finding.
		n.mu.Lock()
		n.cooldown[key] = now
		if len(n.cooldown) > 10000 {
			clear(n.cooldown)
			n.cooldown[key] = now
		}
		n.mu.Unlock()
	default:
		n.dropped.Add(1)
		n.log.Warn("alert queue full; dropping anomaly alert", "kind", a.Kind, "summary", a.Summary)
	}
}

// Run delivers alerts until ctx ends.
func (n *Notifier) Run(ctx context.Context) {
	for _, w := range n.routes {
		go w.run(ctx)
	}
	for {
		select {
		case <-ctx.Done():
			n.dropped.Add(uint64(len(n.queue)))
			return
		case m := <-n.queue:
			switch {
			case m.device != nil:
				if n.inLearning(ctx, m.device.TS) {
					n.learning.Add(1)
					n.log.Debug("new device during learning period; not alerting", "mac", m.device.MAC, "label", m.device.Label)
					continue
				}
				n.dispatch(NewPayload(*m.device), nil, "new device", m.device.MAC)
			case m.anomaly != nil:
				n.dispatch(NewAnomalyPayload(*m.anomaly), m.anomaly, "anomaly", m.anomaly.Summary)
			case m.report != "":
				n.dispatch(NewReportPayload(m.report), nil, "report", m.report)
			}
		}
	}
}

func (n *Notifier) inLearning(ctx context.Context, ts time.Time) bool {
	if n.cfg.Learn <= 0 || n.cfg.Since == nil {
		return false
	}
	since, err := n.cfg.Since(ctx)
	if err != nil || since.IsZero() {
		return true
	}
	return ts.Before(since.Add(n.cfg.Learn))
}

func (n *Notifier) deliver(ctx context.Context, c Channel, p Payload, what, detail string) {
	backoff := n.backoff
	for attempt := 1; ; attempt++ {
		err := c.Send(ctx, p)
		if err == nil {
			n.sent.Add(1)
			n.log.Info("sent alert", "channel", c.Name(), "event", p.Event, "detail", detail)
			return
		}
		if errors.Is(err, errPermanent) || attempt == 4 || ctx.Err() != nil {
			n.failed.Add(1)
			n.log.Warn("alert not delivered", "channel", c.Name(), "event", what, "detail", detail, "err", err)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 4
	}
}

var errPermanent = errors.New("permanent webhook failure")

// NewPayload builds the webhook body for a device.
func NewPayload(d store.NewDevice) Payload {
	var b strings.Builder
	fmt.Fprintf(&b, "New device on the network: %s", safeText(d.Label))
	var detail []string
	if d.IP.IsValid() {
		detail = append(detail, d.IP.String())
	}
	if d.Label != d.MAC {
		detail = append(detail, d.MAC)
	}
	if d.Vendor != "" {
		detail = append(detail, safeText(d.Vendor))
	}
	if len(detail) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(detail, ", "))
	}
	text := b.String()
	p := Payload{Event: "new_device", Text: text, Content: text, Device: &d}
	p.AllowedMentions.Parse = []string{}
	return p
}

// NewAnomalyPayload builds the webhook body for one anomaly finding.
func NewAnomalyPayload(a model.Anomaly) Payload {
	sev := a.Severity
	if sev != "" {
		sev = strings.ToUpper(sev[:1]) + sev[1:]
	}
	text := fmt.Sprintf("%s anomaly: %s", sev, safeText(a.Summary))
	if a.DeviceName != "" {
		text += fmt.Sprintf(" (%s)", safeText(a.DeviceName))
	}
	p := Payload{Event: "anomaly", Text: text, Content: text, Anomaly: &a}
	p.AllowedMentions.Parse = []string{}
	return p
}

// NewReportPayload builds the webhook body for a periodic summary.
func NewReportPayload(text string) Payload {
	p := Payload{Event: "report", Text: text, Content: text}
	p.AllowedMentions.Parse = []string{}
	return p
}

// safeText makes a name from the LAN (a DHCP hostname, say) inert in a chat
// message: no control characters, no Slack <!channel>-style markup or
// links, no @mentions, and a bounded length.
func safeText(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == 64 {
			b.WriteString("…")
			break
		}
		n++
		switch {
		case unicode.IsControl(r):
			b.WriteRune(' ')
		case r == '<':
			b.WriteRune('‹')
		case r == '>':
			b.WriteRune('›')
		case r == '@':
			b.WriteString("@\u200b") // a zero-width space breaks the mention
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
