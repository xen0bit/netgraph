package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
)

// CreateAnnotation stores a human note and puts it on the Flight Recorder
// rail. Notes are user data: retention never deletes them.
func (s *Store) CreateAnnotation(ctx context.Context, a model.Annotation) (*model.Annotation, error) {
	a.Text = strings.TrimSpace(a.Text)
	if a.Text == "" {
		return nil, fmt.Errorf("%w: annotation text is required", ErrInvalid)
	}
	now := s.cfg.Now().UnixMilli()
	if a.TS == 0 {
		a.TS = now
	}
	a.Created = now
	if err := s.w.QueryRowContext(ctx, `INSERT INTO annotations (ts, entity, kind, text, author, created)
		VALUES (?, ?, ?, ?, ?, ?) RETURNING id`, a.TS, a.Entity, a.Kind, a.Text, a.Author, a.Created).Scan(&a.ID); err != nil {
		return nil, err
	}
	title := a.Text
	if a.Kind != "" {
		title = a.Kind + ": " + a.Text
	}
	_, err := s.w.ExecContext(ctx, `INSERT OR IGNORE INTO timeline_events
		(ts, kind, entity_key, title, ref_table, ref_key, attrs)
		VALUES (?, 'annotation', ?, ?, 'annotations', ?, '{}')`,
		a.TS, a.Entity, title, fmt.Sprint(a.ID))
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// Annotations lists notes in a window, newest first.
func (s *Store) Annotations(ctx context.Context, f model.Filter) ([]model.Annotation, error) {
	from, to := s.window(f)
	rows, err := s.r.QueryContext(ctx, `SELECT id, ts, entity, kind, text, author, created
		FROM annotations WHERE ts >= ? AND ts < ? AND (? = '' OR entity = ?)
		ORDER BY ts DESC, id DESC LIMIT ?`, from, to, f.Device, f.Device, limit(f, 500, 10000))
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
	res, err := s.w.ExecContext(ctx, `DELETE FROM annotations WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_, _ = s.w.ExecContext(ctx, `DELETE FROM timeline_events WHERE ref_table = 'annotations' AND ref_key = ?`, fmt.Sprint(id))
	return nil
}

// CreateBookmark marks a moment.
func (s *Store) CreateBookmark(ctx context.Context, b model.Bookmark) (*model.Bookmark, error) {
	b.Name = strings.TrimSpace(b.Name)
	if b.Name == "" {
		return nil, fmt.Errorf("%w: bookmark name is required", ErrInvalid)
	}
	now := s.cfg.Now().UnixMilli()
	if b.TS == 0 {
		b.TS = now
	}
	b.Created = now
	if err := s.w.QueryRowContext(ctx, `INSERT INTO bookmarks (ts, entity, name, created)
		VALUES (?, ?, ?, ?) RETURNING id`, b.TS, b.Entity, b.Name, b.Created).Scan(&b.ID); err != nil {
		return nil, err
	}
	_, err := s.w.ExecContext(ctx, `INSERT OR IGNORE INTO timeline_events
		(ts, kind, entity_key, title, ref_table, ref_key, attrs)
		VALUES (?, 'bookmark', ?, ?, 'bookmarks', ?, '{}')`,
		b.TS, b.Entity, b.Name, fmt.Sprint(b.ID))
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// Bookmarks lists bookmarks in a window, newest first.
func (s *Store) Bookmarks(ctx context.Context, f model.Filter) ([]model.Bookmark, error) {
	from, to := s.window(f)
	rows, err := s.r.QueryContext(ctx, `SELECT id, ts, entity, name, created
		FROM bookmarks WHERE ts >= ? AND ts < ? AND (? = '' OR entity = ?)
		ORDER BY ts DESC, id DESC LIMIT ?`, from, to, f.Device, f.Device, limit(f, 500, 10000))
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
	res, err := s.w.ExecContext(ctx, `DELETE FROM bookmarks WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_, _ = s.w.ExecContext(ctx, `DELETE FROM timeline_events WHERE ref_table = 'bookmarks' AND ref_key = ?`, fmt.Sprint(id))
	return nil
}

// AnnotationAt is a small helper for tests and future callers.
func (s *Store) AnnotationAt(ctx context.Context, id int64) (*model.Annotation, error) {
	var a model.Annotation
	err := s.r.QueryRowContext(ctx, `SELECT id, ts, entity, kind, text, author, created FROM annotations WHERE id = ?`, id).
		Scan(&a.ID, &a.TS, &a.Entity, &a.Kind, &a.Text, &a.Author, &a.Created)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}
