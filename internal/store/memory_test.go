package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
)

func TestAnnotationsAndBookmarks(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	a, err := st.CreateAnnotation(ctx, model.Annotation{TS: testutil.Base.Add(time.Minute).UnixMilli(), Entity: "device:3c:22:fb:01:02:03", Text: "router changed", Kind: "change"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == 0 {
		t.Fatal("annotation id is zero")
	}
	list, err := st.Annotations(ctx, win(0, time.Hour))
	if err != nil || len(list) != 1 || list[0].Text != "router changed" {
		t.Fatalf("annotations = %+v %v", list, err)
	}
	page, err := st.Timeline(ctx, win(0, time.Hour), model.TimelineQuery{Kinds: []string{"annotation"}, Limit: 10})
	if err != nil || len(page.Events) != 1 {
		t.Fatalf("annotation timeline = %+v %v", page, err)
	}
	b, err := st.CreateBookmark(ctx, model.Bookmark{TS: testutil.Base.Add(2 * time.Minute).UnixMilli(), Entity: "device:3c:22:fb:01:02:03", Name: "before restart"})
	if err != nil || b.ID == 0 {
		t.Fatalf("bookmark = %+v %v", b, err)
	}
	bs, err := st.Bookmarks(ctx, win(0, time.Hour))
	if err != nil || len(bs) != 1 || bs[0].Name != "before restart" {
		t.Fatalf("bookmarks = %+v %v", bs, err)
	}
	if err := st.DeleteAnnotation(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAnnotation(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete = %v", err)
	}
	if err := st.DeleteBookmark(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
}
