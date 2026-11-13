package api

import (
	"bytes"
	"container/list"
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// The memo keeps recent answers to the slow reads (Home, the summary, the
// device list, the map), so a page that asks again, another tab, or a second
// person costs nothing, and requests that arrive together share one
// computation. It holds encoded responses, never the store's values, so no
// caller can change what another is given.
//
// A window ending now moves with every request, so it is keyed by its length
// and kept only briefly; a fixed window is kept longer. Every change made
// through the API (labels, profiles, mutes, rules) empties it, and it answers
// nothing older than its TTL, so new data shows within memoLiveTTL.
const (
	memoLiveTTL  = 10 * time.Second
	memoFixedTTL = 2 * time.Minute
	// memoLiveEdge is how close to now a window's end counts as now.
	memoLiveEdge = 15 * time.Second
	memoMaxEntry = 8 << 20
	memoMaxBytes = 64 << 20
	// memoRunTimeout bounds a computation once its first caller has left: it
	// still finishes, so the next request (a reload) finds it done.
	memoRunTimeout = 2 * time.Minute
)

type memo struct {
	mu      sync.Mutex
	gen     uint64
	entries map[string]*list.Element
	lru     *list.List // front: most recently used
	size    int
	flight  map[string]*memoRun
	now     func() time.Time
}

type memoEntry struct {
	key  string
	gen  uint64
	at   time.Time
	ttl  time.Duration
	ctyp string
	body []byte
}

type memoRun struct {
	done   chan struct{}
	status int
	ctyp   string
	body   []byte
}

func newMemo() *memo {
	return &memo{entries: map[string]*list.Element{}, lru: list.New(), flight: map[string]*memoRun{}, now: time.Now}
}

// changed forgets every answer: something they may depend on was edited.
func (m *memo) changed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gen++
	m.entries = map[string]*list.Element{}
	m.lru.Init()
	m.size = 0
}

// key names a request: its route, the caller's role (an answer may depend
// on it), and its query, with a window ending now named by its length.
func (m *memo) key(r *http.Request, role Role) (string, time.Duration) {
	q := r.URL.Query()
	ttl := memoFixedTTL
	now := m.now()
	to := q.Get("to")
	if to == "" || to == "now" {
		ttl = memoLiveTTL
		q.Del("to")
	} else if n, err := strconv.ParseInt(to, 10, 64); err == nil {
		if d := now.Sub(time.UnixMilli(n)); d > -memoLiveEdge && d < memoLiveEdge {
			ttl = memoLiveTTL
			q.Set("to", "live")
			if from, err := strconv.ParseInt(q.Get("from"), 10, 64); err == nil {
				q.Set("from", "span:"+strconv.FormatInt(n-from, 10))
			}
		}
	}
	return r.Pattern + "|" + role.String() + "|" + canonical(q), ttl
}

// canonical is a query's encoding with its keys in order, so the same
// question asked in a different order is the same key.
func canonical(q url.Values) string { return q.Encode() }

// memoized serves h through the memo. A live answer is one about now
// whatever its query says, such as Home's.
func (s *Server) memoized(live bool, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m := s.memo
		id, _ := r.Context().Value(identityKey{}).(Identity)
		key, ttl := m.key(r, id.Role)
		if live {
			ttl = memoLiveTTL
		}
		m.mu.Lock()
		if el, ok := m.entries[key]; ok {
			e := el.Value.(*memoEntry)
			if e.gen == m.gen && m.now().Sub(e.at) < e.ttl {
				m.lru.MoveToFront(el)
				m.mu.Unlock()
				writeMemo(w, http.StatusOK, e.ctyp, e.body)
				return
			}
			m.drop(el)
		}
		run := m.flight[key]
		if run == nil {
			run = &memoRun{done: make(chan struct{})}
			m.flight[key] = run
			go m.lead(r, h, key, ttl, m.gen, run)
		}
		m.mu.Unlock()
		select {
		case <-run.done:
			writeMemo(w, run.status, run.ctyp, run.body)
		case <-r.Context().Done():
		}
	}
}

// lead computes an answer for everyone waiting on run, in a context of its
// own: the caller who started it may leave, and the work is still worth
// finishing.
func (m *memo) lead(r *http.Request, h http.HandlerFunc, key string, ttl time.Duration, gen uint64, run *memoRun) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), memoRunTimeout)
	defer cancel()
	rec := &memoRecorder{header: http.Header{}, status: http.StatusOK}
	defer func() {
		if p := recover(); p != nil {
			slog.Error("panic answering a request", "route", r.Pattern, "panic", p)
			rec = &memoRecorder{header: http.Header{}, status: http.StatusInternalServerError}
		}
		m.mu.Lock()
		delete(m.flight, key)
		run.status, run.ctyp, run.body = rec.status, rec.header.Get("Content-Type"), rec.buf.Bytes()
		if rec.status == http.StatusOK && m.gen == gen && rec.buf.Len() <= memoMaxEntry {
			m.add(&memoEntry{key: key, gen: gen, at: m.now(), ttl: ttl, ctyp: run.ctyp, body: run.body})
		}
		m.mu.Unlock()
		close(run.done)
	}()
	h(rec, r.WithContext(ctx))
}

func (m *memo) add(e *memoEntry) {
	if el, ok := m.entries[e.key]; ok {
		m.drop(el)
	}
	m.entries[e.key] = m.lru.PushFront(e)
	m.size += len(e.body)
	for m.size > memoMaxBytes && m.lru.Len() > 0 {
		m.drop(m.lru.Back())
	}
}

func (m *memo) drop(el *list.Element) {
	e := el.Value.(*memoEntry)
	m.lru.Remove(el)
	delete(m.entries, e.key)
	m.size -= len(e.body)
}

func writeMemo(w http.ResponseWriter, status int, ctyp string, body []byte) {
	if ctyp != "" {
		w.Header().Set("Content-Type", ctyp)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// memoRecorder is an http.ResponseWriter that keeps what it is given.
type memoRecorder struct {
	header http.Header
	status int
	wrote  bool
	buf    bytes.Buffer
}

func (r *memoRecorder) Header() http.Header { return r.header }

func (r *memoRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status, r.wrote = code, true
	}
}

func (r *memoRecorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.buf.Write(b)
}
