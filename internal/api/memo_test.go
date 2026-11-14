package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// memoServer is a Server whose only route counts the times it really ran.
func memoServer(t *testing.T, live bool) (*Server, *atomic.Int32, func(query string) (int, string)) {
	t.Helper()
	s := &Server{memo: newMemo()}
	clock := time.UnixMilli(1_800_000_000_000)
	s.memo.now = func() time.Time { return clock }
	var runs atomic.Int32
	h := s.memoized(live, func(w http.ResponseWriter, r *http.Request) {
		n := runs.Add(1)
		if r.URL.Query().Get("fail") != "" {
			http.Error(w, "no", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"run":%d}`, n)
	})
	get := func(query string) (int, string) {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/x?"+query, nil)
		r.Pattern = "GET /api/v1/x"
		w := httptest.NewRecorder()
		h(w, r)
		return w.Code, w.Body.String()
	}
	return s, &runs, get
}

func TestMemoCachesAndForgets(t *testing.T) {
	s, runs, get := memoServer(t, false)
	if _, b := get("from=-1h"); b != `{"run":1}` {
		t.Fatalf("first = %s", b)
	}
	// The same question, its parameters in another order, is answered from
	// the memo; a different one is not.
	if _, b := get("from=-1h"); b != `{"run":1}` {
		t.Fatalf("repeat = %s", b)
	}
	if _, b := get("from=-1h&device=a"); b != `{"run":2}` {
		t.Fatalf("other = %s", b)
	}
	if _, b := get("device=a&from=-1h"); b != `{"run":2}` {
		t.Fatalf("reordered = %s", b)
	}
	// An edit empties it.
	s.memo.changed()
	if _, b := get("from=-1h"); b != `{"run":3}` {
		t.Fatalf("after a change = %s", b)
	}
	// Errors aren't kept.
	get("fail=1")
	if c, _ := get("fail=1"); c != http.StatusBadRequest || runs.Load() != 5 {
		t.Fatalf("errors: code %d after %d runs", c, runs.Load())
	}
}

func TestMemoLiveWindows(t *testing.T) {
	s, _, get := memoServer(t, false)
	now := s.memo.now()
	at := func(d time.Duration) string { return strconv.FormatInt(now.Add(d).UnixMilli(), 10) }
	// A window ending now is keyed by its length, so a page asking a few
	// seconds later, its edges moved, still finds it.
	if _, b := get("from=" + at(-time.Hour) + "&to=" + at(0)); b != `{"run":1}` {
		t.Fatal(b)
	}
	s.memo.now = func() time.Time { return now.Add(3 * time.Second) }
	if _, b := get("from=" + at(-time.Hour+3*time.Second) + "&to=" + at(3*time.Second)); b != `{"run":1}` {
		t.Fatalf("a moved live window = %s", b)
	}
	// ...but only briefly: new data has to show.
	s.memo.now = func() time.Time { return now.Add(memoLiveTTL + 4*time.Second) }
	if _, b := get("from=" + at(-time.Hour+memoLiveTTL+4*time.Second) + "&to=" + at(memoLiveTTL+4*time.Second)); b != `{"run":2}` {
		t.Fatalf("after the live TTL = %s", b)
	}
	// A fixed window in the past is kept longer.
	if _, b := get("from=" + at(-48*time.Hour) + "&to=" + at(-24*time.Hour)); b != `{"run":3}` {
		t.Fatal(b)
	}
	s.memo.now = func() time.Time { return now.Add(time.Minute) }
	if _, b := get("from=" + at(-48*time.Hour) + "&to=" + at(-24*time.Hour)); b != `{"run":3}` {
		t.Fatalf("a fixed window a minute later = %s", b)
	}
}

func TestMemoSharesOneRun(t *testing.T) {
	s := &Server{memo: newMemo()}
	release := make(chan struct{})
	var runs atomic.Int32
	h := s.memoized(true, func(w http.ResponseWriter, r *http.Request) {
		runs.Add(1)
		<-release
		fmt.Fprint(w, "ok")
	})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodGet, "/api/v1/home", nil)
			r.Pattern = "GET /api/v1/home"
			w := httptest.NewRecorder()
			h(w, r)
			if w.Body.String() != "ok" {
				t.Errorf("body = %q", w.Body.String())
			}
		}()
	}
	// Let them all arrive, then let the one run finish.
	for {
		s.memo.mu.Lock()
		n := len(s.memo.flight)
		s.memo.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	if n := runs.Load(); n != 1 {
		t.Fatalf("ran %d times, want 1", n)
	}
}

// A computation whose first caller leaves still finishes, so the reload
// that follows finds it done.
func TestMemoOutlivesItsCaller(t *testing.T) {
	s := &Server{memo: newMemo()}
	var runs atomic.Int32
	done := make(chan struct{})
	h := s.memoized(true, func(w http.ResponseWriter, r *http.Request) {
		runs.Add(1)
		time.Sleep(30 * time.Millisecond)
		if r.Context().Err() != nil {
			t.Error("the run was cancelled with its caller")
		}
		fmt.Fprint(w, "ok")
		close(done)
	})
	r := httptest.NewRequest(http.MethodGet, "/api/v1/home", nil)
	r.Pattern = "GET /api/v1/home"
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	h(httptest.NewRecorder(), r.WithContext(ctx))
	<-done
	time.Sleep(5 * time.Millisecond)
	w := httptest.NewRecorder()
	h(w, r)
	if w.Body.String() != "ok" || runs.Load() != 1 {
		t.Fatalf("body %q after %d runs", w.Body.String(), runs.Load())
	}
}
