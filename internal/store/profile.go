package store

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"database/sql"

	"github.com/xen0bit/netgraph/internal/classify"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/oui"
)

// typeCacheTTL is how long classifications stand. They read every device's facts,
// and what a device is rarely changes within a minute. A person's edit resets it.
const typeCacheTTL = time.Minute

// serveWindow is how far back the ports a device answered on count as evidence.
const serveWindow = 7 * 24 * time.Hour

type deviceFacts struct {
	id      int64
	mac     string
	verdict classify.Verdict
	user    string // a person's type
	owner   string
	groups  []string
	sameAs  string
}

type typeCache struct {
	mu   sync.Mutex
	at   time.Time
	byID map[int64]*deviceFacts
}

func (c *typeCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = time.Time{}
	c.byID = nil
}

// deviceFacts classifies every device, from everything known about it ever: a
// printer that was quiet this week is still a printer.
func (s *Store) deviceFacts(ctx context.Context) (map[int64]*deviceFacts, error) {
	c := &s.types
	c.mu.Lock()
	defer c.mu.Unlock()
	now := s.cfg.Now()
	if c.byID != nil && now.Sub(c.at) < typeCacheTTL && !now.Before(c.at) {
		return c.byID, nil
	}
	inputs := map[int64]*classify.Input{}
	out := map[int64]*deviceFacts{}
	rows, err := s.r.QueryContext(ctx, `SELECT id, key, attrs FROM entities WHERE kind = 'device'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var key, attrs string
		if err := rows.Scan(&id, &key, &attrs); err != nil {
			return nil, err
		}
		var a map[string]string
		_ = json.Unmarshal([]byte(attrs), &a)
		in := &classify.Input{Role: a["role"]}
		if v := a["vendor"]; v != oui.Randomized {
			in.Vendor = v
		}
		if v := a["dhcp_vendor_class"]; v != "" {
			in.Fingerprints = append(in.Fingerprints, v)
		}
		inputs[id] = in
		d := &deviceFacts{id: id, mac: key, user: a["user_type"], owner: a["owner"], sameAs: a["same_as"]}
		if g := a["groups"]; g != "" {
			d.groups = strings.Split(g, ",")
		}
		out[id] = d
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	facts, err := s.r.QueryContext(ctx, `SELECT f.src, f.rel, b.key, b.label, b.attrs FROM facts f JOIN entities b ON b.id = f.dst
		WHERE f.rel IN (?, ?, ?, ?, ?) ORDER BY f.src, f.rel, b.key`,
		model.RelHostname, model.RelAnnounces, model.RelFingerprint, model.RelUserAgent, model.RelUPnP)
	if err != nil {
		return nil, err
	}
	defer facts.Close()
	for facts.Next() {
		var id int64
		var rel, key, label, attrs string
		if err := facts.Scan(&id, &rel, &key, &label, &attrs); err != nil {
			return nil, err
		}
		in := inputs[id]
		if in == nil {
			continue
		}
		switch rel {
		case model.RelHostname:
			in.Hostnames = append(in.Hostnames, firstNonEmpty(label, key))
		case model.RelAnnounces:
			in.Services = append(in.Services, key)
			var a map[string]string
			_ = json.Unmarshal([]byte(attrs), &a)
			if a["model"] != "" {
				in.Models = append(in.Models, a["model"])
			}
		case model.RelFingerprint:
			in.Fingerprints = append(in.Fingerprints, firstNonEmpty(label, key))
		case model.RelUserAgent:
			in.UserAgents = append(in.UserAgents, key)
		case model.RelUPnP:
			in.UPnP = append(in.UPnP, key)
		}
	}
	if err := facts.Err(); err != nil {
		return nil, err
	}
	ports, err := s.r.QueryContext(ctx, `SELECT DISTINCT client_device, remote_port, proto FROM traffic_hourly WHERE direction = 'in' AND bucket >= ? ORDER BY 1, 2, 3`,
		hourOf(ms(now.Add(-serveWindow))))
	if err != nil {
		return nil, err
	}
	defer ports.Close()
	for ports.Next() {
		var id int64
		var port, proto int
		if err := ports.Scan(&id, &port, &proto); err != nil {
			return nil, err
		}
		if in := inputs[id]; in != nil {
			in.Serves = append(in.Serves, strings.TrimSpace(portProto(port, uint8(proto))))
		}
	}
	if err := ports.Err(); err != nil {
		return nil, err
	}
	for id, in := range inputs {
		out[id].verdict = classify.Classify(*in)
	}
	c.byID, c.at = out, now
	return out, nil
}

// applyProfiles says what each device is, who owns it and what it's grouped in.
// If the classification can't be read, the devices are still worth returning.
func (s *Store) applyProfiles(ctx context.Context, devs []model.Device) {
	if len(devs) == 0 {
		return
	}
	facts, err := s.deviceFacts(ctx)
	if err != nil {
		s.log.Warn("classify devices", "err", err)
		return
	}
	byMAC := make(map[string]*deviceFacts, len(facts))
	for _, f := range facts {
		byMAC[f.mac] = f
	}
	for i := range devs {
		f := byMAC[devs[i].MAC]
		if f == nil {
			continue
		}
		fillProfile(&devs[i], f)
	}
}

func fillProfile(d *model.Device, f *deviceFacts) {
	d.Owner, d.Groups, d.SameAs = f.owner, f.groups, f.sameAs
	if f.user != "" {
		d.Type, d.UserType, d.TypeConfidence = f.user, true, ""
		return
	}
	d.Type, d.TypeConfidence = f.verdict.Type, f.verdict.Confidence
}

// explainType adds the reasons behind a single device's type.
func (s *Store) explainType(ctx context.Context, d *model.Device) {
	facts, err := s.deviceFacts(ctx)
	if err != nil {
		return
	}
	for _, f := range facts {
		if f.mac != d.MAC {
			continue
		}
		fillProfile(d, f)
		d.TypeWhy = make([]model.TypeReason, 0, len(f.verdict.Reasons))
		for _, r := range f.verdict.Reasons {
			d.TypeWhy = append(d.TypeWhy, model.TypeReason(r))
		}
		return
	}
}

// deviceIDsByProfile answers type:printer, owner:alice and group:iot. ok is false
// when the pattern is none of them, as a MAC or a name isn't: "type" is not hex.
func (s *Store) deviceIDsByProfile(ctx context.Context, pattern string) ([]int64, bool, error) {
	key, want, found := strings.Cut(strings.TrimSpace(pattern), ":")
	if !found || (key != "type" && key != "owner" && key != "group") {
		return nil, false, nil
	}
	want = strings.ToLower(want)
	facts, err := s.deviceFacts(ctx)
	if err != nil {
		return nil, true, err
	}
	out := []int64{}
	for id, f := range facts {
		switch key {
		case "type":
			if strings.ToLower(firstNonEmpty(f.user, f.verdict.Type)) == want || (want == "computer" && firstNonEmpty(f.user, f.verdict.Type) == classify.Computer) {
				out = append(out, id)
			}
		case "owner":
			if strings.ToLower(f.owner) == want {
				out = append(out, id)
			}
		case "group":
			if slices.ContainsFunc(f.groups, func(g string) bool { return strings.ToLower(g) == want }) {
				out = append(out, id)
			}
		}
	}
	slices.Sort(out)
	return out, true, nil
}

// MaxProfileText is the longest owner or group name, in characters.
const MaxProfileText = 64

func validProfileText(s string) bool {
	return utf8.RuneCountInString(s) <= MaxProfileText && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}

// SetDeviceProfile records what a person says a device is, and who it belongs to.
func (s *Store) SetDeviceProfile(ctx context.Context, mac string, p model.DeviceProfile) error {
	if s.w == nil {
		return errors.New("database is open read-only")
	}
	m, ok := normMAC(mac)
	if !ok {
		return fmt.Errorf("%w: MAC %q", ErrInvalid, mac)
	}
	set := map[string]string{}
	if p.Type != nil {
		if *p.Type != "" && !classify.Valid(*p.Type) {
			return fmt.Errorf("%w: type is one of %v", ErrInvalid, classify.Types)
		}
		set["user_type"] = *p.Type
	}
	if p.Owner != nil {
		o := strings.TrimSpace(*p.Owner)
		if !validProfileText(o) {
			return fmt.Errorf("%w: an owner is at most %d printable characters", ErrInvalid, MaxProfileText)
		}
		set["owner"] = o
	}
	if p.Groups != nil {
		var groups []string
		for _, g := range p.Groups {
			g = strings.TrimSpace(g)
			if g == "" {
				continue
			}
			// A filter's word can't hold a space, and the list is stored with commas.
			if !validProfileText(g) || strings.ContainsAny(g, ", \t") {
				return fmt.Errorf("%w: a group is one word of at most %d characters", ErrInvalid, MaxProfileText)
			}
			if !slices.Contains(groups, g) {
				groups = append(groups, g)
			}
		}
		set["groups"] = strings.Join(groups, ",")
	}
	return s.editDevice(ctx, func(g *ingester) error { return g.deviceAttrs(ctx, m, set) })
}

// deviceAttrs writes a person's attributes on a device; an empty value removes one.
func (g *ingester) deviceAttrs(ctx context.Context, mac string, set map[string]string) error {
	var seen int64
	err := g.tx.QueryRowContext(ctx, `SELECT last_seen FROM entities WHERE kind = ? AND key = ?`, model.KindDevice, mac).Scan(&seen)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: device %s", ErrNotFound, mac)
	}
	if err != nil {
		return err
	}
	if _, err := g.entity(ctx, model.KindDevice, mac, seen, nil); err != nil {
		return err
	}
	e := g.row(model.KindDevice, mac)
	for k, v := range set {
		if v == "" {
			delete(e.attrs, k)
		} else {
			e.attrs[k] = v
		}
	}
	b, _ := json.Marshal(e.attrs)
	if _, err := g.tx.ExecContext(ctx, `UPDATE entities SET attrs = ? WHERE id = ?`, string(b), e.id); err != nil {
		return err
	}
	e.dirty = false
	return nil
}

// --- private addresses ---------------------------------------------------------

// A value shared by more devices than this says nothing about any one of them:
// every iPhone on an iOS version asks DHCP the same thing.
const linkMaxSharers = 4

// linkOverlap is how long two addresses may both be active and still be one device
// that switched address.
const linkOverlap = 5 * time.Minute

// linkGeneric are hostnames many devices use, which can't identify one.
var linkGeneric = map[string]bool{"android": true, "iphone": true, "ipad": true, "localhost": true, "espressif": true, "unknown": true, "esp": true, "galaxy": true}

// linkWeights: only a name or an announced service can carry a suggestion; the
// rest add confidence to one. Fingerprints are shared by whole product lines.
var linkWeights = map[string]int{"hostname": 4, "service": 4, "fingerprint": 1, "user_agent": 1}

// DeviceLinks suggests which private MACs are devices already known under another
// address: the same name or services, and never online together. Suggestions a
// person has answered aren't repeated.
func (s *Store) DeviceLinks(ctx context.Context) ([]model.DeviceLink, error) {
	type dev struct {
		id          int64
		mac         string
		random      bool
		first, last int64
		sameAs      string
		not         map[string]bool
		values      map[[2]string]bool
	}
	rows, err := s.r.QueryContext(ctx, `SELECT id, key, attrs, first_seen, last_seen FROM entities WHERE kind = 'device'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devs := map[int64]*dev{}
	for rows.Next() {
		d := &dev{not: map[string]bool{}, values: map[[2]string]bool{}}
		var attrs string
		if err := rows.Scan(&d.id, &d.mac, &attrs, &d.first, &d.last); err != nil {
			return nil, err
		}
		var a map[string]string
		_ = json.Unmarshal([]byte(attrs), &a)
		d.random, d.sameAs = a["vendor"] == oui.Randomized, a["same_as"]
		for _, m := range strings.Split(a["not_same_as"], ",") {
			d.not[m] = true
		}
		devs[d.id] = d
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	facts, err := s.r.QueryContext(ctx, `SELECT f.src, f.rel, b.key, b.label FROM facts f JOIN entities b ON b.id = f.dst WHERE f.rel IN (?, ?, ?, ?) ORDER BY b.key`,
		model.RelHostname, model.RelAnnounces, model.RelFingerprint, model.RelUserAgent)
	if err != nil {
		return nil, err
	}
	defer facts.Close()
	owners := map[[2]string]map[int64]bool{}
	for facts.Next() {
		var id int64
		var rel, key, label string
		if err := facts.Scan(&id, &rel, &key, &label); err != nil {
			return nil, err
		}
		d := devs[id]
		if d == nil {
			continue
		}
		signal := map[string]string{model.RelHostname: "hostname", model.RelAnnounces: "service", model.RelFingerprint: "fingerprint", model.RelUserAgent: "user_agent"}[rel]
		value := firstNonEmpty(label, key)
		if signal == "hostname" && linkGeneric[strings.ToLower(value)] {
			continue
		}
		v := [2]string{signal, value}
		d.values[v] = true
		if owners[v] == nil {
			owners[v] = map[int64]bool{}
		}
		owners[v][id] = true
	}
	if err := facts.Err(); err != nil {
		return nil, err
	}
	type found struct {
		a, b    *dev
		reasons []model.LinkReason
		score   int
	}
	var finds []found
	for _, r := range devs {
		if !r.random || r.sameAs != "" {
			continue
		}
		scores := map[int64]*found{}
		for v := range r.values {
			if len(owners[v]) > linkMaxSharers {
				continue
			}
			for id := range owners[v] {
				c := devs[id]
				// The candidate came first, and stopped before this one started.
				if c == r || r.not[c.mac] || c.first >= r.first || c.last > r.first+linkOverlap.Milliseconds() {
					continue
				}
				f := scores[id]
				if f == nil {
					f = &found{a: r, b: c}
					scores[id] = f
				}
				f.score += linkWeights[v[0]]
				f.reasons = append(f.reasons, model.LinkReason{Signal: v[0], Value: v[1]})
			}
		}
		var best *found
		for _, f := range scores {
			if f.score < linkWeights["hostname"] {
				continue
			}
			// The most evidence, then the most recently seen: a stable order.
			if best == nil || f.score > best.score || (f.score == best.score && (f.b.last > best.b.last || (f.b.last == best.b.last && f.b.mac < best.b.mac))) {
				best = f
			}
		}
		if best != nil {
			finds = append(finds, *best)
		}
	}
	out := []model.DeviceLink{}
	if len(finds) == 0 {
		return out, nil
	}
	lookup := func(mac string) (model.Device, error) {
		d, err := s.Entity(ctx, model.EntityID(model.KindDevice, mac), model.Filter{From: s.cfg.Now().Add(-time.Minute), To: s.cfg.Now()})
		if err != nil {
			return model.Device{}, err
		}
		if d.Device != nil {
			return *d.Device, nil
		}
		return model.Device{ID: d.ID, MAC: mac, Label: d.Label, FirstSeen: d.FirstSeen, LastSeen: d.LastSeen}, nil
	}
	for _, f := range finds {
		a, err := lookup(f.a.mac)
		if err != nil {
			return nil, err
		}
		b, err := lookup(f.b.mac)
		if err != nil {
			return nil, err
		}
		slices.SortFunc(f.reasons, func(x, y model.LinkReason) int {
			return cmp.Or(cmp.Compare(linkWeights[y.Signal], linkWeights[x.Signal]), cmp.Compare(x.Signal, y.Signal), cmp.Compare(x.Value, y.Value))
		})
		conf := classify.Medium
		if f.score >= 6 {
			conf = classify.High
		}
		out = append(out, model.DeviceLink{Device: a, Same: b, Confidence: conf, Reasons: f.reasons})
	}
	slices.SortFunc(out, func(x, y model.DeviceLink) int {
		return cmp.Or(cmp.Compare(y.Device.FirstSeen, x.Device.FirstSeen), cmp.Compare(x.Device.MAC, y.Device.MAC))
	})
	return out, nil
}

// LinkDecisions.
const (
	LinkSame      = "same"      // this private MAC is that device
	LinkDifferent = "different" // it isn't; don't suggest it again
	LinkUndo      = "undo"      // forget the answer, and what "same" copied
)

// DecideLink records a person's answer. "same" links the two and copies the name,
// owner and groups across where this device has none; the data stays under each
// MAC, so "undo" can take it all back.
func (s *Store) DecideLink(ctx context.Context, mac, other, decision string) error {
	if s.w == nil {
		return errors.New("database is open read-only")
	}
	m, ok := normMAC(mac)
	if !ok {
		return fmt.Errorf("%w: MAC %q", ErrInvalid, mac)
	}
	o := ""
	if decision != LinkUndo {
		if o, ok = normMAC(other); !ok || o == m {
			return fmt.Errorf("%w: the other MAC %q", ErrInvalid, other)
		}
	}
	read := func(key string) (map[string]string, error) {
		var attrs string
		err := s.w.QueryRowContext(ctx, `SELECT attrs FROM entities WHERE kind = ? AND key = ?`, model.KindDevice, key).Scan(&attrs)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: device %s", ErrNotFound, key)
		}
		if err != nil {
			return nil, err
		}
		var a map[string]string
		_ = json.Unmarshal([]byte(attrs), &a)
		return a, nil
	}
	mine, err := read(m)
	if err != nil {
		return err
	}
	set := map[string]string{}
	label := ""
	clearLabel := false
	switch decision {
	case LinkSame:
		theirs, err := read(o)
		if err != nil {
			return err
		}
		set["same_as"] = o
		var copied []string
		for _, k := range []string{"owner", "groups", "user_type"} {
			if mine[k] == "" && theirs[k] != "" {
				set[k] = theirs[k]
				copied = append(copied, k)
			}
		}
		if mine["user_label"] == "" && theirs["user_label"] != "" {
			label = theirs["user_label"]
			copied = append(copied, "user_label")
		}
		set["link_copied"] = strings.Join(copied, ",")
	case LinkDifferent:
		not := slices.DeleteFunc(strings.Split(mine["not_same_as"], ","), func(s string) bool { return s == "" || s == o })
		set["not_same_as"] = strings.Join(append(not, o), ",")
	case LinkUndo:
		set["same_as"], set["not_same_as"], set["link_copied"] = "", "", ""
		for _, k := range strings.Split(mine["link_copied"], ",") {
			if k == "user_label" {
				clearLabel = true
			} else if k != "" {
				set[k] = ""
			}
		}
	default:
		return fmt.Errorf("%w: decision is same, different or undo", ErrInvalid)
	}
	return s.editDevice(ctx, func(g *ingester) error {
		if err := g.deviceAttrs(ctx, m, set); err != nil {
			return err
		}
		if label != "" {
			return g.userLabel(ctx, m, label)
		}
		if clearLabel {
			return g.userLabel(ctx, m, "")
		}
		return nil
	})
}

// dropDeadLinks removes links to devices that no longer exist, so an erased MAC
// doesn't live on in another device's attributes. What a link copied stays: that
// was a person's name for the device that remains.
func dropDeadLinks(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, attrs FROM entities WHERE kind = 'device' AND (attrs LIKE '%same_as%')`)
	if err != nil {
		return err
	}
	type edit struct {
		id    int64
		attrs map[string]string
	}
	var edits []edit
	for rows.Next() {
		var e edit
		var attrs string
		if err := rows.Scan(&e.id, &attrs); err != nil {
			rows.Close()
			return err
		}
		if json.Unmarshal([]byte(attrs), &e.attrs) == nil {
			edits = append(edits, e)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	exists := func(mac string) (bool, error) {
		var n int
		err := tx.QueryRowContext(ctx, `SELECT count(*) FROM entities WHERE kind = 'device' AND key = ?`, mac).Scan(&n)
		return n > 0, err
	}
	for _, e := range edits {
		changed := false
		if m := e.attrs["same_as"]; m != "" {
			ok, err := exists(m)
			if err != nil {
				return err
			}
			if !ok {
				delete(e.attrs, "same_as")
				delete(e.attrs, "link_copied")
				changed = true
			}
		}
		if list := e.attrs["not_same_as"]; list != "" {
			var keep []string
			for _, m := range strings.Split(list, ",") {
				ok, err := exists(m)
				if err != nil {
					return err
				}
				if ok {
					keep = append(keep, m)
				} else {
					changed = true
				}
			}
			if len(keep) == 0 {
				delete(e.attrs, "not_same_as")
			} else {
				e.attrs["not_same_as"] = strings.Join(keep, ",")
			}
		}
		if changed {
			b, _ := json.Marshal(e.attrs)
			if _, err := tx.ExecContext(ctx, `UPDATE entities SET attrs = ? WHERE id = ?`, string(b), e.id); err != nil {
				return err
			}
		}
	}
	return nil
}

// --- presence ---------------------------------------------------------------------

// Silence this much shorter than the bucket's step doesn't end an interval.
const presenceGapMinute = 15 * time.Minute

// Presence says when each device moved traffic in a window: from per-minute totals
// while they last, then hourly.
func (s *Store) Presence(ctx context.Context, f model.Filter) (*model.Presence, error) {
	from, to := s.window(f)
	if to <= from {
		return nil, fmt.Errorf("%w: from must be before to", ErrInvalid)
	}
	table, step, gap, precision := "traffic_minute", time.Minute, presenceGapMinute, "minute"
	if from < ms(s.cfg.Now().Add(-s.cfg.MinuteRetention)) {
		table, step, gap, precision = "traffic_hourly", time.Hour, 2*time.Hour, "hour"
	}
	stepMS := step.Milliseconds()
	w := &where{}
	w.add("bucket >= ? AND bucket < ? AND multicast = 0", from-pmod(from, stepMS), to)
	if f.Device != "" {
		ids, err := s.deviceIDs(ctx, f.Device)
		if err != nil {
			return nil, err
		}
		w.add("client_device IN (" + idList(ids) + ")")
	}
	rows, err := s.r.QueryContext(ctx, `SELECT DISTINCT client_device, bucket FROM `+table+` WHERE `+w.sql()+` ORDER BY client_device, bucket`, w.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byDev := map[int64][][2]int64{}
	for rows.Next() {
		var id, bucket int64
		if err := rows.Scan(&id, &bucket); err != nil {
			return nil, err
		}
		list := byDev[id]
		start, end := max(bucket, from), min(bucket+stepMS, to)
		if n := len(list); n > 0 && start-list[n-1][1] <= gap.Milliseconds() {
			list[n-1][1] = end
		} else {
			list = append(list, [2]int64{start, end})
		}
		byDev[id] = list
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := &model.Presence{FromMS: from, ToMS: to, Precision: precision, GapMS: gap.Milliseconds(), Devices: []model.PresenceDevice{}}
	if len(byDev) == 0 {
		return out, nil
	}
	ids := make([]int64, 0, len(byDev))
	for id := range byDev {
		ids = append(ids, id)
	}
	names, err := s.r.QueryContext(ctx, `SELECT id, key, label, attrs FROM entities WHERE kind = 'device' AND id IN (`+idList(ids)+`)`)
	if err != nil {
		return nil, err
	}
	defer names.Close()
	facts, err := s.deviceFacts(ctx)
	if err != nil {
		return nil, err
	}
	for names.Next() {
		var id int64
		var key, label, attrs string
		if err := names.Scan(&id, &key, &label, &attrs); err != nil {
			return nil, err
		}
		var a map[string]string
		_ = json.Unmarshal([]byte(attrs), &a)
		p := model.PresenceDevice{ID: model.EntityID(model.KindDevice, key), Label: deviceLabel(key, label, a), Intervals: byDev[id]}
		if pf := facts[id]; pf != nil {
			p.Type, p.Owner = firstNonEmpty(pf.user, pf.verdict.Type), pf.owner
		}
		out.Devices = append(out.Devices, p)
	}
	if err := names.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(out.Devices, func(a, b model.PresenceDevice) int {
		return cmp.Or(cmp.Compare(strings.ToLower(a.Owner), strings.ToLower(b.Owner)), cmp.Compare(strings.ToLower(a.Label), strings.ToLower(b.Label)), cmp.Compare(a.ID, b.ID))
	})
	return out, nil
}
