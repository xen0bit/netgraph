package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
)

// Limits on what people type. Rail titles carry these to every client.
const (
	maxNoteText  = 4096
	maxShortText = 256
)

// inTx runs fn in one write transaction. The writer pool has one connection,
// so this queues behind an ingest batch rather than interleaving with it.
func (s *Store) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	if s.w == nil {
		return errors.New("database is open read-only")
	}
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// normEntity validates an entity ID someone typed. Device IDs are normalised
// so that db forget finds whatever was attached to the device.
func normEntity(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", nil
	}
	kind, key, ok := model.SplitEntityID(id)
	if !ok || kind == "" || key == "" || len(id) > maxShortText {
		return "", fmt.Errorf("%w: entity %q is not kind:key", ErrInvalid, id)
	}
	if kind == model.KindDevice {
		mac, ok := normMAC(key)
		if !ok {
			return "", fmt.Errorf("%w: device %q is not a MAC", ErrInvalid, key)
		}
		return model.EntityID(kind, mac), nil
	}
	return id, nil
}

// CreateAnnotation stores a human note and puts it on the Flight Recorder
// rail. Notes are user data: retention never deletes them.
func (s *Store) CreateAnnotation(ctx context.Context, a model.Annotation) (*model.Annotation, error) {
	a.Text = strings.TrimSpace(a.Text)
	if a.Text == "" {
		return nil, fmt.Errorf("%w: annotation text is required", ErrInvalid)
	}
	if len(a.Text) > maxNoteText || len(a.Kind) > maxShortText || len(a.Author) > maxShortText || a.TS < 0 {
		return nil, fmt.Errorf("%w: annotation field out of range", ErrInvalid)
	}
	var err error
	if a.Entity, err = normEntity(a.Entity); err != nil {
		return nil, err
	}
	now := s.cfg.Now().UnixMilli()
	if a.TS == 0 {
		a.TS = now
	}
	a.Created = now
	title := a.Text
	if a.Kind != "" {
		title = a.Kind + ": " + a.Text
	}
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `INSERT INTO annotations (ts, entity, kind, text, author, created)
			VALUES (?, ?, ?, ?, ?, ?) RETURNING id`, a.TS, a.Entity, a.Kind, a.Text, a.Author, a.Created).Scan(&a.ID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO timeline_events
			(ts, kind, entity_key, title, ref_table, ref_key, attrs)
			VALUES (?, 'annotation', ?, ?, 'annotations', ?, '{}')`,
			a.TS, a.Entity, title, fmt.Sprint(a.ID))
		return err
	})
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// Annotations lists notes in a window, newest first.
func (s *Store) Annotations(ctx context.Context, f model.Filter) ([]model.Annotation, error) {
	from, to := s.window(f)
	rows, err := s.r.QueryContext(ctx, `SELECT id, ts, entity, kind, text, author, created
		FROM annotations WHERE ts >= ? AND ts < ? AND (? = '' OR entity = ? OR entity = 'device:' || lower(?))
		ORDER BY ts DESC, id DESC LIMIT ?`, from, to, f.Device, f.Device, f.Device, limit(f, 500, 10000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Annotation{}
	for rows.Next() {
		var a model.Annotation
		if err := rows.Scan(&a.ID, &a.TS, &a.Entity, &a.Kind, &a.Text, &a.Author, &a.Created); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteAnnotation removes a note and its rail event.
func (s *Store) DeleteAnnotation(ctx context.Context, id int64) error {
	return s.deleteMemory(ctx, "annotations", id)
}

// CreateBookmark marks a moment.
func (s *Store) CreateBookmark(ctx context.Context, b model.Bookmark) (*model.Bookmark, error) {
	b.Name = strings.TrimSpace(b.Name)
	if b.Name == "" {
		return nil, fmt.Errorf("%w: bookmark name is required", ErrInvalid)
	}
	if len(b.Name) > maxShortText || b.TS < 0 {
		return nil, fmt.Errorf("%w: bookmark field out of range", ErrInvalid)
	}
	var err error
	if b.Entity, err = normEntity(b.Entity); err != nil {
		return nil, err
	}
	now := s.cfg.Now().UnixMilli()
	if b.TS == 0 {
		b.TS = now
	}
	b.Created = now
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `INSERT INTO bookmarks (ts, entity, name, created)
			VALUES (?, ?, ?, ?) RETURNING id`, b.TS, b.Entity, b.Name, b.Created).Scan(&b.ID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO timeline_events
			(ts, kind, entity_key, title, ref_table, ref_key, attrs)
			VALUES (?, 'bookmark', ?, ?, 'bookmarks', ?, '{}')`,
			b.TS, b.Entity, b.Name, fmt.Sprint(b.ID))
		return err
	})
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// Bookmarks lists bookmarks in a window, newest first.
func (s *Store) Bookmarks(ctx context.Context, f model.Filter) ([]model.Bookmark, error) {
	from, to := s.window(f)
	rows, err := s.r.QueryContext(ctx, `SELECT id, ts, entity, name, created
		FROM bookmarks WHERE ts >= ? AND ts < ? AND (? = '' OR entity = ? OR entity = 'device:' || lower(?))
		ORDER BY ts DESC, id DESC LIMIT ?`, from, to, f.Device, f.Device, f.Device, limit(f, 500, 10000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Bookmark{}
	for rows.Next() {
		var b model.Bookmark
		if err := rows.Scan(&b.ID, &b.TS, &b.Entity, &b.Name, &b.Created); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// DeleteBookmark removes a bookmark and its rail event.
func (s *Store) DeleteBookmark(ctx context.Context, id int64) error {
	return s.deleteMemory(ctx, "bookmarks", id)
}

// deleteMemory removes one row of a fixed table and its rail event together.
func (s *Store) deleteMemory(ctx context.Context, table string, id int64) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM timeline_events WHERE ref_table = ? AND ref_key = ?`, table, fmt.Sprint(id))
		return err
	})
}
