package store

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
)

const (
	// findingScanWindow is what a scan reads: the checks judge hours, so a shorter
	// one would change what they find. The first scan looks back further.
	findingScanWindow  = time.Hour
	findingFirstWindow = 24 * time.Hour
	// A finding unseen for this long has stopped happening.
	findingStale = 7 * 24 * time.Hour
	// Findings about one device this close together are one story.
	findingGroupGap = time.Hour
	maxFindingNote  = 500
	maxFindings     = 2000
)

// A finding "fine" for good: a mute this long is the allowlist.
const findingFineFor = 100 * 365 * 24 * time.Hour

func findingKey(a model.Anomaly) string { return a.Kind + "|" + a.Device + "|" + a.Entity }

// FindingEvent is what a scan changed about a finding, for notifications.
type FindingEvent struct {
	Finding model.Finding
	Type    string // new or recurred
}

// Finding event types.
const (
	FindingNew      = "new"
	FindingRecurred = "recurred"
)

// ScanFindings runs the checks over the recent past and records what they find. A
// finding is new the first time, and returns from resolved only for something that
// happened after it was last seen: rereading the same event must not reopen it.
func (s *Store) ScanFindings(ctx context.Context) ([]FindingEvent, error) {
	if s.w == nil {
		return nil, errors.New("database is open read-only")
	}
	now := s.cfg.Now()
	s.findMu.Lock()
	defer s.findMu.Unlock()
	window := findingScanWindow
	if s.findScanned.IsZero() {
		window = findingFirstWindow
	}
	rep, err := s.Anomalies(ctx, model.Filter{From: now.Add(-window), To: now})
	if err != nil {
		return nil, err
	}
	s.findScanned, s.findLearning = now, rep.Learning

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var events []FindingEvent
	for _, a := range rep.Anomalies {
		ev, err := upsertFinding(ctx, tx, a, now)
		if err != nil {
			return nil, err
		}
		if ev != nil {
			events = append(events, *ev)
		}
	}
	// Whatever has gone quiet for a week has stopped, whoever hasn't said so.
	if _, err := tx.ExecContext(ctx, `UPDATE findings SET status = 'resolved', status_at = ?, auto_resolved = 1
		WHERE status IN ('new', 'seen', 'acknowledged') AND last_seen < ?`, ms(now), ms(now.Add(-findingStale))); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

func upsertFinding(ctx context.Context, tx *sql.Tx, a model.Anomaly, now time.Time) (*FindingEvent, error) {
	evidence, _ := json.Marshal(a.Evidence)
	key := findingKey(a)
	var id, last int64
	var status, severity string
	err := tx.QueryRowContext(ctx, `SELECT id, last_seen, status, severity FROM findings WHERE key = ?`, key).Scan(&id, &last, &status, &severity)
	if errors.Is(err, sql.ErrNoRows) {
		res, err := tx.ExecContext(ctx, `INSERT INTO findings (key, kind, severity, device, device_name, entity, summary, evidence, first_seen, last_seen, status_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, key, a.Kind, a.Severity, a.Device, a.DeviceName, a.Entity, a.Summary, string(evidence), a.TS, a.TS, ms(now))
		if err != nil {
			return nil, err
		}
		fid, err := res.LastInsertId()
		if err != nil {
			return nil, err
		}
		return &FindingEvent{Type: FindingNew, Finding: model.Finding{Anomaly: a, ID: fid, Status: model.FindingNew, FirstSeen: a.TS, LastSeen: a.TS, Occurrences: 1, StatusAt: ms(now)}}, nil
	}
	if err != nil {
		return nil, err
	}
	// The same event, read again by an overlapping scan: nothing has happened.
	if a.TS <= last {
		return nil, nil
	}
	// Severity only rises while it stays open; a return starts over.
	sev := a.Severity
	reopened := status == model.FindingResolved
	if !reopened && model.SeverityRank(severity) > model.SeverityRank(sev) {
		sev = severity
	}
	if reopened {
		if _, err := tx.ExecContext(ctx, `UPDATE findings SET status = 'new', status_at = ?, auto_resolved = 0, recurrences = recurrences + 1 WHERE id = ?`, ms(now), id); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE findings SET severity = ?, device_name = ?, summary = ?, evidence = ?, last_seen = ?, occurrences = occurrences + 1 WHERE id = ?`,
		sev, a.DeviceName, a.Summary, string(evidence), a.TS, id); err != nil {
		return nil, err
	}
	if !reopened {
		return nil, nil
	}
	return &FindingEvent{Type: FindingRecurred, Finding: model.Finding{Anomaly: a, ID: id, Status: model.FindingNew, LastSeen: a.TS, StatusAt: ms(now)}}, nil
}

const findingCols = `id, kind, severity, device, device_name, entity, summary, evidence, first_seen, last_seen, occurrences, status, status_at, auto_resolved, recurrences, note`

func scanFinding(row interface{ Scan(...any) error }) (model.Finding, error) {
	var f model.Finding
	var evidence string
	var auto int
	err := row.Scan(&f.ID, &f.Kind, &f.Severity, &f.Device, &f.DeviceName, &f.Entity, &f.Summary, &evidence, &f.FirstSeen, &f.LastSeen, &f.Occurrences, &f.Status, &f.StatusAt, &auto, &f.Recurrences, &f.Note)
	if err != nil {
		return f, err
	}
	f.TS = f.LastSeen
	f.AutoResolved = auto != 0
	_ = json.Unmarshal([]byte(evidence), &f.Evidence)
	return f, nil
}

// Findings lists findings, most urgent first, grouped into stories.
func (s *Store) Findings(ctx context.Context, q model.FindingQuery) (*model.FindingList, error) {
	w := &where{}
	switch q.Status {
	case "":
	case "open":
		w.add("status IN ('new', 'seen', 'acknowledged')")
	case model.FindingNew, model.FindingSeen, model.FindingAcknowledged, model.FindingResolved, model.FindingDismissed:
		w.add("status = ?", q.Status)
	default:
		return nil, fmt.Errorf("%w: status %q", ErrInvalid, q.Status)
	}
	if q.SinceMS > 0 {
		w.add("last_seen >= ?", q.SinceMS)
	}
	if q.ToMS > 0 {
		w.add("first_seen < ?", q.ToMS)
	}
	if q.Device != "" {
		w.add("device = ?", q.Device)
	}
	sqlStr := `SELECT ` + findingCols + ` FROM findings`
	if c := w.sql(); c != "" {
		sqlStr += ` WHERE ` + c
	}
	n := q.Limit
	if n <= 0 || n > maxFindings {
		n = 500
	}
	rows, err := s.r.QueryContext(ctx, sqlStr+` ORDER BY last_seen DESC, id DESC LIMIT ?`, append(w.args, n)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := &model.FindingList{Findings: []model.Finding{}, Groups: []model.FindingGroup{}, Counts: map[string]int{}}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out.Findings = append(out.Findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	counts, err := s.r.QueryContext(ctx, `SELECT status, count(*) FROM findings GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer counts.Close()
	for counts.Next() {
		var st string
		var c int
		if err := counts.Scan(&st, &c); err != nil {
			return nil, err
		}
		out.Counts[st] = c
	}
	if err := counts.Err(); err != nil {
		return nil, err
	}
	s.findMu.Lock()
	if !s.findScanned.IsZero() {
		out.ScannedMS, out.Learning = ms(s.findScanned), s.findLearning
	}
	s.findMu.Unlock()
	out.Groups = groupFindings(out.Findings)
	return out, nil
}

// groupFindings tells stories: one device's findings close together in time. The
// list itself stays flat and whole; a group refers to it by ID.
func groupFindings(list []model.Finding) []model.FindingGroup {
	byDevice := map[string][]model.Finding{}
	for _, f := range list {
		if f.Device != "" {
			byDevice[f.Device] = append(byDevice[f.Device], f)
		}
	}
	groups := []model.FindingGroup{}
	for dev, fs := range byDevice {
		slices.SortFunc(fs, func(a, b model.Finding) int {
			return cmp.Or(cmp.Compare(a.LastSeen, b.LastSeen), cmp.Compare(a.ID, b.ID))
		})
		var cur *model.FindingGroup
		flush := func() {
			if cur != nil && len(cur.IDs) > 1 {
				groups = append(groups, *cur)
			}
			cur = nil
		}
		for _, f := range fs {
			if cur == nil || f.FirstSeen-cur.ToMS > findingGroupGap.Milliseconds() {
				flush()
				cur = &model.FindingGroup{Device: dev, DeviceName: f.DeviceName, FromMS: f.FirstSeen, ToMS: f.LastSeen, Severity: f.Severity}
			}
			cur.IDs = append(cur.IDs, f.ID)
			cur.ToMS = max(cur.ToMS, f.LastSeen)
			cur.FromMS = min(cur.FromMS, f.FirstSeen)
			if model.SeverityRank(f.Severity) > model.SeverityRank(cur.Severity) {
				cur.Severity = f.Severity
			}
		}
		flush()
	}
	slices.SortFunc(groups, func(a, b model.FindingGroup) int {
		return cmp.Or(cmp.Compare(b.ToMS, a.ToMS), cmp.Compare(a.Device, b.Device))
	})
	return groups
}

// Finding is one finding, explained: why it fires, what to do about it, and whether
// it is usual for this device.
func (s *Store) Finding(ctx context.Context, id int64) (*model.Finding, error) {
	f, err := scanFinding(s.r.QueryRowContext(ctx, `SELECT `+findingCols+` FROM findings WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	e := explainFinding(f.Kind)
	f.Why, f.Advice = e.why, e.advice
	if f.Device != "" {
		var same, fine int
		if err := s.r.QueryRowContext(ctx, `SELECT count(*), coalesce(sum(status = 'dismissed'), 0) FROM findings WHERE device = ? AND kind = ? AND id != ?`, f.Device, f.Kind, f.ID).Scan(&same, &fine); err != nil {
			return nil, err
		}
		f.Usual = usualFor(f, same, fine)
	}
	return &f, nil
}

// usualFor says, from what's recorded, whether this is normal for the device.
func usualFor(f model.Finding, same, fine int) string {
	switch {
	case fine > 0:
		return fmt.Sprintf("You've marked %d similar %s fine for this device.", fine, plural(fine, "finding", "findings"))
	case f.Recurrences > 0:
		return fmt.Sprintf("It has come back %d %s after being resolved.", f.Recurrences, plural(f.Recurrences, "time", "times"))
	case same > 0:
		return fmt.Sprintf("This device has had %d other %s of this kind.", same, plural(same, "finding", "findings"))
	case f.Occurrences > 1:
		return fmt.Sprintf("It has happened %d times since it was first seen.", f.Occurrences)
	}
	return "This is the first time netgraph has seen this from this device."
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// SetFindingStatus records what a person decided. An empty status keeps the current
// one, to change only the note. Dismissing is FindingFine's job, which also stops it
// coming back.
func (s *Store) SetFindingStatus(ctx context.Context, id int64, status, note string) error {
	if s.w == nil {
		return errors.New("database is open read-only")
	}
	switch status {
	case "", model.FindingNew, model.FindingSeen, model.FindingAcknowledged, model.FindingResolved:
	default:
		return fmt.Errorf("%w: status is new, seen, acknowledged or resolved", ErrInvalid)
	}
	note = strings.TrimSpace(note)
	if len(note) > maxFindingNote {
		return fmt.Errorf("%w: a note is at most %d bytes", ErrInvalid, maxFindingNote)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var res sql.Result
	var err error
	if status == "" {
		res, err = s.w.ExecContext(ctx, `UPDATE findings SET note = ? WHERE id = ?`, note, id)
	} else {
		res, err = s.w.ExecContext(ctx, `UPDATE findings SET status = ?, status_at = ?, auto_resolved = 0, note = CASE WHEN ? != '' THEN ? ELSE note END WHERE id = ?`,
			status, ms(s.cfg.Now()), note, note, id)
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkFindingsSeen turns every new finding seen: someone looked at the list.
func (s *Store) MarkFindingsSeen(ctx context.Context) error {
	if s.w == nil {
		return errors.New("database is open read-only")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.w.ExecContext(ctx, `UPDATE findings SET status = 'seen', status_at = ? WHERE status = 'new'`, ms(s.cfg.Now()))
	return err
}

// FindingFine says this is normal: for this device, findings of this kind about
// this thing stop being reported. It's a mute that doesn't run out, so it can be
// reviewed and removed with the others.
func (s *Store) FindingFine(ctx context.Context, id int64, note string) error {
	if s.w == nil {
		return errors.New("database is open read-only")
	}
	f, err := s.Finding(ctx, id)
	if err != nil {
		return err
	}
	if err := s.SetAnomalyMute(ctx, model.AnomalyMute{Kind: f.Kind, Device: f.Device, Entity: f.Entity, Until: s.cfg.Now().Add(findingFineFor).UnixMilli(), Note: firstNonEmpty(note, "marked fine")}); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.w.ExecContext(ctx, `UPDATE findings SET status = 'dismissed', status_at = ?, auto_resolved = 0, note = CASE WHEN ? != '' THEN ? ELSE note END WHERE id = ?`, ms(s.cfg.Now()), note, note, id)
	return err
}

type findingText struct{ why, advice string }

// explainFinding is what each kind means, in words for someone who didn't write
// the check. It says what fired; what to do is a suggestion.
func explainFinding(kind string) findingText {
	if t, ok := findingTexts[kind]; ok {
		return t
	}
	return findingText{"One of netgraph's checks flagged this.", "Look at the evidence, and at the device's recent activity."}
}

var findingTexts = map[string]findingText{
	model.AnomalyNewDevice: {
		"A device used an address on your network for the first time.",
		"If you recognise it, name it. If you don't, see what it talks to, and check who has your Wi-Fi password.",
	},
	model.AnomalyNewDestination: {
		"A device that usually talks to only a few places reached one it hadn't in the last week.",
		"Usually an update or a new app. It matters more on something fixed-purpose, like a camera or a plug.",
	},
	model.AnomalyUploadSpike: {
		"A device sent far more than its busiest hour of the last week.",
		"A backup or a video upload explains most of these. If nothing should be uploading, see where it went.",
	},
	model.AnomalyBeacon: {
		"A device connects to the same place on a steady schedule.",
		"Update checks and telemetry do this all the time. Malware does too, so check you recognise the destination.",
	},
	model.AnomalyDNSFailures: {
		"A device looked up many names that don't exist.",
		"Often a misconfigured app or a blocklist. Malware searching for its server looks the same.",
	},
	model.AnomalyDNSTunnel: {
		"A device looked up many long, unique names under one site, which is how data gets smuggled through DNS.",
		"Some security and CDN products do this too. If you don't recognise the site, investigate the device.",
	},
	model.AnomalyRogueAP: {
		"A network name appeared with an access point that doesn't match the others using it.",
		"Check it isn't your own new access point. A copy of your network name is how people get lured onto a fake one.",
	},
	model.AnomalyScan: {
		"An address outside tried many ports, or one port on many of your addresses.",
		"Background noise if you expose services to the internet. Check nothing answered that shouldn't have.",
	},
	model.AnomalyBruteForce: {
		"Many short sessions reached a login service from outside, which is what password guessing looks like.",
		"Use strong keys or passwords on that service, and consider blocking the source or closing the port.",
	},
	model.AnomalyNewService: {
		"A device here started answering a port for clients outside.",
		"Fine if you just opened it. If not, find out what's listening, and whether your router forwarded it on purpose.",
	},
	model.AnomalyInboundSurge: {
		"Far more connections came from outside than in any recent hour.",
		"A popular moment or a crawler can do this; so can an attack. See which addresses and which service.",
	},
	model.AnomalyARPConflict: {
		"Two devices held the same address at once.",
		"Often a static address clashing with DHCP. It can also be someone intercepting traffic, so check you recognise both.",
	},
	model.AnomalyNameMismatch: {
		"A connection asked for a name the device never looked up, or a different name shares the address.",
		"Usually a CDN, proxy or hard-coded address. If it is unexpected, inspect the destination and the device.",
	},
	model.AnomalyRogueDHCP: {
		"A device other than the router answered DHCP requests on your network.",
		"Devices listening to it can be sent anywhere. Unplug or reconfigure it, unless it's meant to be your DHCP server.",
	},
	model.AnomalyDeauthFlood: {
		"An access point's clients were disconnected many times, which can be jamming or an attack on the Wi-Fi handshake.",
		"Note when it happens. If it repeats, consider WPA3 with protected management frames.",
	},
	model.AnomalySensorSilent: {
		"A sensor stopped reporting, so netgraph can't see what it was watching.",
		"Check the sensor and its link to this server. Nothing it missed can be recovered.",
	},
}
