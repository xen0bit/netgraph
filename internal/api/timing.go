package api

import (
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// slowRequest is how long an API answer may take before the log says so.
const slowRequest = time.Second

// routeTimes counts requests and their time per route, by the mux's pattern
// (GET /api/v1/devices/{mac}): a fixed set, whatever the paths asked for.
type routeTimes struct {
	mu sync.Mutex
	by map[string]*routeTime
}

type routeTime struct {
	n, slow uint64
	total   time.Duration
}

func (t *routeTimes) observe(route string, d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.by == nil {
		t.by = map[string]*routeTime{}
	}
	rt := t.by[route]
	if rt == nil {
		rt = &routeTime{}
		t.by[route] = rt
	}
	rt.n++
	rt.total += d
	if d >= slowRequest {
		rt.slow++
	}
}

// each calls fn for each route in order.
func (t *routeTimes) each(fn func(route string, rt routeTime)) {
	t.mu.Lock()
	routes := make([]string, 0, len(t.by))
	for r := range t.by {
		routes = append(routes, r)
	}
	snap := make(map[string]routeTime, len(t.by))
	for r, rt := range t.by {
		snap[r] = *rt
	}
	t.mu.Unlock()
	sort.Strings(routes)
	for _, r := range routes {
		fn(r, snap[r])
	}
}

// timed records how long r took, and logs it when slow. The live stream and
// exports run as long as they're read, so they're left out.
func (s *Server) timed(r *http.Request, start time.Time) {
	if !strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api/v1/live" || r.URL.Path == "/api/v1/export" || r.Pattern == "" {
		return
	}
	d := time.Since(start)
	s.routeTimes.observe(r.Pattern, d)
	if d >= slowRequest && !strings.HasSuffix(r.Pattern, "/export") {
		// The path and the query's names, not their values: a query can hold
		// a token or a person's search.
		q := r.URL.Query()
		names := make([]string, 0, len(q))
		for k := range q {
			names = append(names, k)
		}
		sort.Strings(names)
		s.log.Info("slow request", "route", r.Pattern, "params", strings.Join(names, ","), "duration", d.Round(time.Millisecond))
	}
}
