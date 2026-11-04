// Package hass publishes to Home Assistant over MQTT, using its discovery
// convention: named devices appear as presence trackers, and findings as a count
// and as events, with no configuration on the Home Assistant side.
//
// It's opt-in, because it sends names and presence to a broker. By default only
// devices a person named or gave an owner are published: a network's worth of
// private MACs would bury the ones anyone cares about.
package hass

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/mqtt"
)

// activeWithin is how recently a device must have moved traffic to count as home.
// The same as Home's "Here now".
const activeWithin = 10 * time.Minute

// Source is what the bridge reads.
type Source interface {
	Devices(ctx context.Context, f model.Filter) ([]model.Device, error)
	Findings(ctx context.Context, q model.FindingQuery) (*model.FindingList, error)
}

// Config configures a Bridge.
type Config struct {
	Options mqtt.Options
	Prefix  string // this server's topics; default netgraph
	AllDevs bool   // every device, not only named ones
	Every   time.Duration
	Logger  *slog.Logger
	Now     func() time.Time
}

// ParseURL reads mqtt://user:pass@host:1883/prefix?devices=all (mqtts for TLS).
func ParseURL(raw string) (Config, error) {
	u, err := url.Parse(raw)
	if err != nil {
		// url's error repeats the address, password and all.
		return Config{}, errors.New("not a URL")
	}
	var c Config
	port := "1883"
	switch u.Scheme {
	case "mqtt":
	case "mqtts":
		port = "8883"
		c.Options.TLS = &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
	default:
		return c, fmt.Errorf("the scheme is %q; want mqtt or mqtts", u.Scheme)
	}
	if u.Hostname() == "" {
		return c, errors.New("no host")
	}
	if u.Port() != "" {
		port = u.Port()
	}
	c.Options.Addr = hostPort(u.Hostname(), port)
	if u.User != nil {
		c.Options.Username = u.User.Username()
		c.Options.Password, _ = u.User.Password()
	}
	c.Prefix = strings.Trim(u.Path, "/")
	if strings.ContainsAny(c.Prefix, "+#") {
		return c, errors.New("the topic prefix can't hold + or #")
	}
	switch u.Query().Get("devices") {
	case "", "named":
	case "all":
		c.AllDevs = true
	default:
		return c, errors.New("devices is named or all")
	}
	return c, nil
}

func hostPort(h, p string) string {
	if strings.Contains(h, ":") {
		return "[" + h + "]:" + p
	}
	return h + ":" + p
}

// Bridge keeps a broker up to date. Run it for as long as the server runs.
type Bridge struct {
	cfg    Config
	src    Source
	log    *slog.Logger
	events chan event
	// What this process has published, so it can take back a device that's gone or
	// no longer named: a retained message would otherwise outlive db forget.
	published map[string]bool
}

type event struct {
	kind string
	f    model.Finding
}

// New returns a Bridge.
func New(cfg Config, src Source) *Bridge {
	if cfg.Prefix == "" {
		cfg.Prefix = "netgraph"
	}
	if cfg.Every <= 0 {
		cfg.Every = time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Options.ClientID == "" {
		cfg.Options.ClientID = "netgraph-" + strings.ReplaceAll(cfg.Prefix, "/", "-")
	}
	cfg.Options.WillTopic = cfg.Prefix + "/status"
	cfg.Options.WillBody = []byte("offline")
	cfg.Options.WillRetain = true
	return &Bridge{cfg: cfg, src: src, log: cfg.Logger, events: make(chan event, 64), published: map[string]bool{}}
}

// Event kinds, as Home Assistant shows them.
const (
	FindingEventNew      = "new"
	FindingEventRecurred = "recurred"
)

// Finding queues a finding to publish. If the broker's away, it's dropped: it's an
// event, and the count and the inbox still hold it.
func (b *Bridge) Finding(kind string, f model.Finding) {
	select {
	case b.events <- event{kind, f}:
	default:
		b.log.Warn("mqtt queue full; dropping a finding", "kind", f.Kind)
	}
}

// Run connects, publishes, and reconnects with a backoff, until ctx ends.
func (b *Bridge) Run(ctx context.Context) {
	delay := time.Second
	for ctx.Err() == nil {
		c, err := mqtt.Dial(ctx, b.cfg.Options)
		if err != nil {
			b.log.Warn("mqtt connect", "addr", b.cfg.Options.Addr, "err", err)
		} else {
			delay = time.Second
			b.log.Info("mqtt connected", "addr", b.cfg.Options.Addr, "prefix", b.cfg.Prefix)
			err := b.serve(ctx, c)
			c.Close()
			if ctx.Err() != nil {
				return
			}
			b.log.Warn("mqtt connection ended", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, 5*time.Minute)
	}
}

func (b *Bridge) serve(ctx context.Context, c *mqtt.Client) error {
	if err := c.Publish(b.cfg.Prefix+"/status", []byte("online"), true); err != nil {
		return err
	}
	if err := b.announceFindings(c); err != nil {
		return err
	}
	if err := b.sync(ctx, c); err != nil {
		return err
	}
	t := time.NewTicker(b.cfg.Every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = c.Publish(b.cfg.Prefix+"/status", []byte("offline"), true)
			return ctx.Err()
		case <-c.Done():
			return c.Err()
		case <-t.C:
			if err := b.sync(ctx, c); err != nil {
				return err
			}
		case e := <-b.events:
			if err := b.publishEvent(c, e); err != nil {
				return err
			}
		}
	}
}

// Topic ID: colons aren't welcome in a Home Assistant object ID.
func objectID(mac string) string { return strings.ReplaceAll(strings.ToLower(mac), ":", "") }

func discoveryTopic(component, object string) string {
	return "homeassistant/" + component + "/netgraph_" + object + "/config"
}

func (b *Bridge) availability() []map[string]string {
	return []map[string]string{{"topic": b.cfg.Prefix + "/status"}}
}

func (b *Bridge) hub() map[string]any {
	return map[string]any{"identifiers": []string{"netgraph_" + objectID(b.cfg.Prefix)}, "name": "netgraph", "manufacturer": "netgraph", "model": "network sensor"}
}

func (b *Bridge) announceFindings(c *mqtt.Client) error {
	state := b.cfg.Prefix + "/findings/state"
	sensor, err := json.Marshal(map[string]any{
		"name": "Open findings", "unique_id": "netgraph_open_findings", "state_topic": state, "icon": "mdi:shield-alert-outline",
		"state_class": "measurement", "device": b.hub(), "availability": b.availability(),
	})
	if err != nil {
		return err
	}
	if err := c.Publish(discoveryTopic("sensor", "open_findings"), sensor, true); err != nil {
		return err
	}
	ev, err := json.Marshal(map[string]any{
		"name": "Finding", "unique_id": "netgraph_finding", "state_topic": b.cfg.Prefix + "/findings/event", "event_types": []string{"new", "recurred"},
		"device": b.hub(), "availability": b.availability(),
	})
	if err != nil {
		return err
	}
	return c.Publish(discoveryTopic("event", "finding"), ev, true)
}

func (b *Bridge) publishEvent(c *mqtt.Client, e event) error {
	body, err := json.Marshal(map[string]any{
		"event_type": e.kind, "kind": e.f.Kind, "severity": e.f.Severity, "summary": e.f.Summary,
		"device": e.f.Device, "device_name": e.f.DeviceName, "ts": e.f.TS,
	})
	if err != nil {
		return err
	}
	return c.Publish(b.cfg.Prefix+"/findings/event", body, false)
}

func (b *Bridge) wanted(d model.Device) bool {
	return b.cfg.AllDevs || d.UserLabel || d.Owner != ""
}

// sync publishes every wanted device's presence and the count of open findings, and
// takes back whatever it published before that's no longer wanted.
func (b *Bridge) sync(ctx context.Context, c *mqtt.Client) error {
	now := b.cfg.Now()
	devs, err := b.src.Devices(ctx, model.Filter{From: now.Add(-7 * 24 * time.Hour), To: now})
	if err != nil {
		// Not the broker's fault: keep the connection, and try again next time.
		b.log.Warn("mqtt: reading devices", "err", err)
		return nil
	}
	current := map[string]bool{}
	for _, d := range devs {
		if !b.wanted(d) {
			continue
		}
		obj := objectID(d.MAC)
		current[obj] = true
		if err := b.publishDevice(c, d, obj, now); err != nil {
			return err
		}
	}
	gone := []string{}
	for obj := range b.published {
		if !current[obj] {
			gone = append(gone, obj)
		}
	}
	slices.Sort(gone)
	for _, obj := range gone {
		// An empty retained message removes it, and removes the entity.
		if err := c.Publish(discoveryTopic("device_tracker", obj), nil, true); err != nil {
			return err
		}
		if err := c.Publish(b.stateTopic(obj), nil, true); err != nil {
			return err
		}
		delete(b.published, obj)
	}
	l, err := b.src.Findings(ctx, model.FindingQuery{Status: "open", Limit: 1})
	if err != nil {
		b.log.Warn("mqtt: reading findings", "err", err)
		return nil
	}
	open := l.Counts[model.FindingNew] + l.Counts[model.FindingSeen] + l.Counts[model.FindingAcknowledged]
	return c.Publish(b.cfg.Prefix+"/findings/state", fmt.Appendf(nil, "%d", open), true)
}

func (b *Bridge) stateTopic(obj string) string { return b.cfg.Prefix + "/device/" + obj + "/state" }

func (b *Bridge) publishDevice(c *mqtt.Client, d model.Device, obj string, now time.Time) error {
	state := "not_home"
	if d.ActiveTo >= now.Add(-activeWithin).UnixMilli() {
		state = "home"
	}
	// Discovery on every sync, so a rename reaches Home Assistant; it's cheap, and
	// Home Assistant ignores a repeat.
	info := map[string]any{"identifiers": []string{"netgraph_" + obj}, "name": d.Label, "connections": [][]string{{"mac", d.MAC}}}
	if d.Vendor != "" {
		info["manufacturer"] = d.Vendor
	}
	cfg, err := json.Marshal(map[string]any{
		"name": nil, "unique_id": "netgraph_" + obj, "state_topic": b.stateTopic(obj), "source_type": "router",
		"payload_home": "home", "payload_not_home": "not_home", "device": info, "availability": b.availability(),
	})
	if err != nil {
		return err
	}
	if err := c.Publish(discoveryTopic("device_tracker", obj), cfg, true); err != nil {
		return err
	}
	if err := c.Publish(b.stateTopic(obj), []byte(state), true); err != nil {
		return err
	}
	b.published[obj] = true
	return nil
}
