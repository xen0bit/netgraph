// Package alert posts new-device notifications to a webhook.
//
// The payload is JSON that common receivers understand without glue: Slack
// and Mattermost read "text", Discord reads "content", and anything else can
// use the structured "device" object. Delivery is asynchronous and bounded:
// the ingest path only enqueues, a full queue drops (and logs) rather than
// blocking, and each post is retried a few times with backoff.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/xen0bit/netgraph/internal/store"
)

// Config configures a Notifier.
type Config struct {
	// URL receives a POST per new device.
	URL string
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
}

// Payload is the JSON posted for one new device.
type Payload struct {
	Event   string          `json:"event"` // "new_device"
	Text    string          `json:"text"`
	Content string          `json:"content"`
	Device  store.NewDevice `json:"device"`
	// AllowedMentions stops Discord from turning text into pings.
	AllowedMentions struct {
		Parse []string `json:"parse"`
	} `json:"allowed_mentions"`
}

// Notifier delivers alerts. Notify is safe for concurrent use.
type Notifier struct {
	cfg     Config
	log     *slog.Logger
	queue   chan store.NewDevice
	backoff time.Duration // first retry delay; tests shorten it
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
	return &Notifier{cfg: cfg, log: cfg.Logger, queue: make(chan store.NewDevice, cfg.Queue), backoff: time.Second}
}

// SetSince sets Config.Since, for when the store is opened after the
// notifier is created (the store's callback is the notifier). Call it
// before Run.
func (n *Notifier) SetSince(f func(context.Context) (time.Time, error)) { n.cfg.Since = f }

// Notify enqueues an alert without blocking. It is store.Config.OnNewDevice.
func (n *Notifier) Notify(d store.NewDevice) {
	select {
	case n.queue <- d:
	default:
		n.log.Warn("alert queue full; dropping new-device alert", "mac", d.MAC)
	}
}

// Run delivers alerts until ctx ends.
func (n *Notifier) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case d := <-n.queue:
			if n.learning(ctx, d.TS) {
				n.log.Debug("new device during learning period; not alerting", "mac", d.MAC, "label", d.Label)
				continue
			}
			n.deliver(ctx, d)
		}
	}
}

func (n *Notifier) learning(ctx context.Context, ts time.Time) bool {
	if n.cfg.Learn <= 0 || n.cfg.Since == nil {
		return false
	}
	since, err := n.cfg.Since(ctx)
	if err != nil || since.IsZero() {
		return true
	}
	return ts.Before(since.Add(n.cfg.Learn))
}

func (n *Notifier) deliver(ctx context.Context, d store.NewDevice) {
	body, err := json.Marshal(NewPayload(d))
	if err != nil {
		return
	}
	backoff := n.backoff
	for attempt := 1; ; attempt++ {
		err := n.post(ctx, body)
		if err == nil {
			n.log.Info("sent new-device alert", "mac", d.MAC, "label", d.Label)
			return
		}
		if attempt == 4 || ctx.Err() != nil {
			n.log.Warn("new-device alert not delivered", "mac", d.MAC, "err", err)
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

func (n *Notifier) post(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.cfg.Client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook: %s", resp.Status)
	}
	return nil
}

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
	p := Payload{Event: "new_device", Text: text, Content: text, Device: d}
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
