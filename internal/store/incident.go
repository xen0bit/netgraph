package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
)

// CreateIncident pins an anomaly (or a manual window) as a saved object.
func (s *Store) CreateIncident(ctx context.Context, a model.Anomaly, title string, from, to time.Time) (*model.Incident, error) {
	if title == "" {
		title = a.Summary
	}
	if title == "" {
		title = strings.ReplaceAll(a.Kind, "_", " ")
	}
	if from.IsZero() {
		from = time.UnixMilli(a.TS).Add(-10 * time.Minute)
	}
	if to.IsZero() {
		to = time.UnixMilli(a.TS).Add(10 * time.Minute)
	}
	now := s.cfg.Now().UnixMilli()
	b, _ := json.Marshal(a)
	var id int64
	err := s.w.QueryRowContext(ctx, `INSERT INTO incidents
		(opened, updated, start_ts, end_ts, kind, severity, status, title, summary, anomaly)
		VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?) RETURNING id`,
		now, now, ms(from), ms(to), a.Kind, a.Severity, title, a.Summary, string(b)).Scan(&id)
	if err != nil {
		return nil, err
	}
	for _, e := range []string{a.Device, a.Entity} {
		if e == "" {
			continue
		}
		if _, err := s.w.ExecContext(ctx, `INSERT OR IGNORE INTO incident_entities (incident_id, entity, role) VALUES (?, ?, 'subject')`, id, e); err != nil {
			return nil, err
		}
	}
	for k := range a.Evidence {
		ev := "anomaly:" + a.Kind + ":" + strconv.FormatInt(a.TS, 10) + ":" + k
		if _, err := s.w.ExecContext(ctx, `INSERT OR IGNORE INTO incident_evidence (incident_id, evidence, pinned) VALUES (?, ?, 1)`, id, ev); err != nil {
			return nil, err
		}
	}
	return s.Incident(ctx, id)
}

// Incidents lists saved investigations, newest first.
func (s *Store) Incidents(ctx context.Context, status string, limit int) ([]model.Incident, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.r.QueryContext(ctx, `SELECT id, opened, updated, start_ts, end_ts, kind, severity, status, title, summary
		FROM incidents WHERE (? = '' OR status = ?) ORDER BY updated DESC LIMIT ?`, status, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Incident{}
	for rows.Next() {
		var in model.Incident
		if err := rows.Scan(&in.ID, &in.OpenedMS, &in.UpdatedMS, &in.StartMS, &in.EndMS, &in.Kind, &in.Severity, &in.Status, &in.Title, &in.Summary); err != nil {
			return nil, err
		}
		in.Entities, _ = s.incidentEntities(ctx, in.ID)
		out = append(out, in)
	}
	return out, rows.Err()
}

func (s *Store) incidentEntities(ctx context.Context, id int64) ([]string, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT entity FROM incident_entities WHERE incident_id = ? ORDER BY entity`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Incident returns one incident with notes and pinned evidence.
func (s *Store) Incident(ctx context.Context, id int64) (*model.Incident, error) {
	var in model.Incident
	err := s.r.QueryRowContext(ctx, `SELECT id, opened, updated, start_ts, end_ts, kind, severity, status, title, summary
		FROM incidents WHERE id = ?`, id).
		Scan(&in.ID, &in.OpenedMS, &in.UpdatedMS, &in.StartMS, &in.EndMS, &in.Kind, &in.Severity, &in.Status, &in.Title, &in.Summary)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	in.Entities, _ = s.incidentEntities(ctx, id)
	return &in, nil
}

// IncidentDetail adds notes and evidence.
func (s *Store) IncidentDetail(ctx context.Context, id int64) (*model.IncidentDetail, error) {
	in, err := s.Incident(ctx, id)
	if err != nil {
		return nil, err
	}
	d := &model.IncidentDetail{Incident: *in}
	rows, err := s.r.QueryContext(ctx, `SELECT id, incident_id, ts, author, body FROM incident_notes WHERE incident_id = ? ORDER BY ts, id`, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var n model.IncidentNote
		if err := rows.Scan(&n.ID, &n.IncidentID, &n.TS, &n.Author, &n.Body); err != nil {
			rows.Close()
			return nil, err
		}
		d.Notes = append(d.Notes, n)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	ev, err := s.r.QueryContext(ctx, `SELECT evidence FROM incident_evidence WHERE incident_id = ? ORDER BY evidence`, id)
	if err != nil {
		return nil, err
	}
	for ev.Next() {
		var e string
		if err := ev.Scan(&e); err != nil {
			ev.Close()
			return nil, err
		}
		d.Evidence = append(d.Evidence, model.EvidenceRef{Kind: "incident", ID: e})
	}
	if err := ev.Close(); err != nil {
		return nil, err
	}
	return d, nil
}

// UpdateIncident changes status/title/summary and optionally adds a note.
func (s *Store) UpdateIncident(ctx context.Context, id int64, status, title, summary, note, author string) (*model.Incident, error) {
	now := s.cfg.Now().UnixMilli()
	if status == "" && title == "" && summary == "" && note == "" {
		return s.Incident(ctx, id)
	}
	_, err := s.w.ExecContext(ctx, `UPDATE incidents SET updated = ?,
		status = CASE WHEN ? != '' THEN ? ELSE status END,
		title = CASE WHEN ? != '' THEN ? ELSE title END,
		summary = CASE WHEN ? != '' THEN ? ELSE summary END
		WHERE id = ?`, now, status, status, title, title, summary, summary, id)
	if err != nil {
		return nil, err
	}
	if note != "" {
		_, err = s.w.ExecContext(ctx, `INSERT INTO incident_notes (incident_id, ts, author, body) VALUES (?, ?, ?, ?)`, id, now, author, note)
		if err != nil {
			return nil, err
		}
	}
	return s.Incident(ctx, id)
}

// PinEvidence adds an evidence reference to an incident.
func (s *Store) PinEvidence(ctx context.Context, id int64, evidence string) error {
	if evidence == "" {
		return fmt.Errorf("%w: empty evidence", ErrInvalid)
	}
	_, err := s.w.ExecContext(ctx, `INSERT OR IGNORE INTO incident_evidence (incident_id, evidence, pinned) VALUES (?, ?, 1)`, id, evidence)
	return err
}

// DeleteIncident removes an incident and its notes/evidence.
func (s *Store) DeleteIncident(ctx context.Context, id int64) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM incidents WHERE id = ?`, id)
	if err != nil {
		return err
	}
	_, _ = s.w.ExecContext(ctx, `DELETE FROM incident_entities WHERE incident_id = ?`, id)
	_, _ = s.w.ExecContext(ctx, `DELETE FROM incident_notes WHERE incident_id = ?`, id)
	_, _ = s.w.ExecContext(ctx, `DELETE FROM incident_evidence WHERE incident_id = ?`, id)
	return nil
}

// Autopsy builds a deterministic evidence reel for an anomaly. It is
// deliberately conservative: every scene is backed by a record or says why
// it cannot be.
func (s *Store) Autopsy(ctx context.Context, a model.Anomaly, f model.Filter) (*model.Autopsy, error) {
	from, to := s.window(f)
	if a.TS != 0 {
		from = min(from, a.TS-10*60_000)
		to = max(to, a.TS+10*60_000)
	}
	subject := a.Device
	if subject == "" {
		subject = a.Entity
	}
	out := &model.Autopsy{FromMS: from, ToMS: to, Generated: s.cfg.Now().UnixMilli(), Anomaly: &a}
	if subject != "" {
		out.Entities = append(out.Entities, subject)
	}
	ev := make([]model.EvidenceRef, 0, len(a.Evidence))
	for k, v := range a.Evidence {
		ev = append(ev, model.EvidenceRef{Kind: "anomaly", ID: a.Kind + ":" + strconv.FormatInt(a.TS, 10) + ":" + k, TS: a.TS, Text: v})
	}
	slices.SortFunc(ev, func(x, y model.EvidenceRef) int { return strings.Compare(x.ID, y.ID) })
	intro := autopsyIntro(a.Kind)
	out.Scenes = append(out.Scenes, model.Scene{
		ID: "finding", AtMS: a.TS, Title: strings.ReplaceAll(a.Kind, "_", " "),
		Narrative: intro + " " + a.Summary, Camera: model.Camera{Focus: subject}, Evidence: ev, Severity: a.Severity,
	})
	if subject == "" {
		out.Gaps = append(out.Gaps, "the finding names no entity, so the camera cannot follow one")
		return out, nil
	}
	sf := model.Filter{From: time.UnixMilli(from), To: time.UnixMilli(to)}
	st, err := s.Story(ctx, subject, sf)
	if err != nil {
		out.Gaps = append(out.Gaps, "the subject is not in the recorded window")
		return out, nil
	}
	if st.Label != "" {
		out.Entities = append(out.Entities, st.Entity)
		out.Scenes = append(out.Scenes, model.Scene{
			ID: "subject", AtMS: from, Title: "Subject",
			Narrative: fmt.Sprintf("%s (%s) has %d recorded intervals in this window.", st.Label, st.Entity, len(st.Segments)),
			Camera:    model.Camera{Focus: st.Entity},
			Evidence:  st.Evidence,
		})
	}
	if len(st.Segments) > 0 {
		first := st.Segments[0]
		out.Scenes = append(out.Scenes, model.Scene{
			ID: "first", AtMS: first.FromMS, Title: "First recorded activity",
			Narrative: fmt.Sprintf("%s began at %s; the evidence is %s.", first.Label, time.UnixMilli(first.FromMS).UTC().Format(time.RFC3339), first.Kind),
			Camera:    model.Camera{Focus: st.Entity},
			Evidence:  first.Evidence,
		})
		last := st.Segments[len(st.Segments)-1]
		out.Scenes = append(out.Scenes, model.Scene{
			ID: "last", AtMS: last.FromMS, Title: "Latest recorded activity",
			Narrative: fmt.Sprintf("The latest interval is %s at %s.", last.Label, time.UnixMilli(last.FromMS).UTC().Format(time.RFC3339)),
			Camera:    model.Camera{Focus: st.Entity},
			Evidence:  last.Evidence,
		})
	}
	if len(st.Milestones) > 0 {
		out.Scenes = append(out.Scenes, model.Scene{
			ID: "sequence", AtMS: st.Milestones[0].TS, Title: "Sequence",
			Narrative: fmt.Sprintf("%d identity or lookup milestones are recorded; the first is %s.", len(st.Milestones), st.Milestones[0].Title),
			Camera:    model.Camera{Focus: st.Entity},
		})
	}
	if len(st.Gaps) > 0 {
		out.Gaps = append(out.Gaps, st.Gaps...)
	}
	slices.SortFunc(out.Scenes, func(x, y model.Scene) int {
		return cmpScene(x, y)
	})
	return out, nil
}

func autopsyIntro(kind string) string {
	switch kind {
	case model.AnomalyDeauthFlood:
		return "A burst of deauthentication frames is a common precursor to a handshake capture; this reel follows the AP and affected clients."
	case model.AnomalyRogueDHCP:
		return "A DHCP server other than the expected one answered; the reel follows the offer and the clients that may have accepted it."
	case model.AnomalyRogueAP:
		return "An access point used an SSID that belongs to another BSSID; the reel compares the legitimate and unexpected radios."
	case model.AnomalyDNSTunnel:
		return "Many long, unique names under one site can indicate DNS tunnelling; the reel shows the names, clients and rate."
	case model.AnomalyARPConflict:
		return "Two devices claimed one address; the reel shows the claimants and the traffic that followed."
	case model.AnomalyScan:
		return "A source touched many ports or hosts; the reel shows the targets and whether anything answered."
	case model.AnomalySensorSilent:
		return "A sensor stopped reporting; the reel shows the last health data and what other sensors saw."
	default:
		return "This reconstruction is built only from recorded evidence; each scene links to the record behind it."
	}
}

func cmpScene(a, b model.Scene) int {
	if a.AtMS != b.AtMS {
		if a.AtMS < b.AtMS {
			return -1
		}
		return 1
	}
	return strings.Compare(a.ID, b.ID)
}

// IncidentAutopsy loads an incident's pinned anomaly and rebuilds its reel.
func (s *Store) IncidentAutopsy(ctx context.Context, id int64) (*model.Autopsy, error) {
	var raw string
	var start, end int64
	err := s.r.QueryRowContext(ctx, `SELECT anomaly, start_ts, end_ts FROM incidents WHERE id = ?`, id).Scan(&raw, &start, &end)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var a model.Anomaly
	_ = json.Unmarshal([]byte(raw), &a)
	f := model.Filter{From: time.UnixMilli(start), To: time.UnixMilli(end)}
	out, err := s.Autopsy(ctx, a, f)
	if err != nil {
		return nil, err
	}
	out.Incident = id
	return out, nil
}
