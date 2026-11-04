package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/store"
	"github.com/xen0bit/netgraph/internal/wire"
)

func authServer(t *testing.T, cfg Config) (*httptest.Server, *store.Store, *Server) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "ng.db"), store.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg.Store = st
	s := New(cfg)
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return srv, st, s
}

type call struct {
	method, path, body string
	token, cookie      string
	headers            map[string]string
}

func do(t *testing.T, srv *httptest.Server, c call) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(c.method, srv.URL+c.path, strings.NewReader(c.body))
	if err != nil {
		t.Fatal(err)
	}
	if c.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.cookie != "" {
		req.Header.Set("Cookie", sessionCookie+"="+c.cookie)
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

const (
	readAPI   = "/api/v1/sensors"
	note      = "/api/v1/annotations"
	noteBody  = `{"ts": 1000, "kind": "note", "text": "hello"}`
	auditPath = "/api/v1/audit"
)

// Who can reach what, for every arrangement of tokens.
func TestRoleMatrix(t *testing.T) {
	type want struct{ read, write, admin int }
	for _, c := range []struct {
		name string
		cfg  Config
		who  map[string]want
	}{
		{
			"no tokens: open, as ever", Config{},
			map[string]want{"": {200, 200, 200}, "stale": {200, 200, 200}},
		},
		{
			"a read token alone does everything, as ever", Config{ReadToken: "r"},
			map[string]want{"": {401, 401, 401}, "x": {401, 401, 401}, "r": {200, 200, 200}},
		},
		{
			"an operator token makes the read token read-only", Config{ReadToken: "r", OperatorToken: "o"},
			map[string]want{"": {401, 401, 401}, "r": {200, 403, 403}, "o": {200, 200, 200}},
		},
		{
			"all three", Config{ReadToken: "r", OperatorToken: "o", AdminToken: "a"},
			map[string]want{"r": {200, 403, 403}, "o": {200, 200, 403}, "a": {200, 200, 200}, "x": {401, 401, 401}},
		},
		{
			"no read token: reading stays open, writing doesn't", Config{OperatorToken: "o"},
			map[string]want{"": {200, 403, 403}, "o": {200, 200, 200}, "stale": {200, 403, 403}},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv, _, _ := authServer(t, c.cfg)
			for tok, w := range c.who {
				if resp, body := do(t, srv, call{method: "GET", path: readAPI, token: tok}); resp.StatusCode != w.read {
					t.Errorf("token %q read: %d %s", tok, resp.StatusCode, body)
				}
				if resp, body := do(t, srv, call{method: "POST", path: note, body: noteBody, token: tok}); resp.StatusCode != w.write {
					t.Errorf("token %q write: %d %s", tok, resp.StatusCode, body)
				}
				if resp, body := do(t, srv, call{method: "GET", path: auditPath, token: tok}); resp.StatusCode != w.admin {
					t.Errorf("token %q admin: %d %s", tok, resp.StatusCode, body)
				}
			}
		})
	}
}

// Nothing that changes anything is open to a viewer: every such route is listed here
// by method, so a new one has to be classified.
func TestEveryChangeNeedsOperator(t *testing.T) {
	srv, _, _ := authServer(t, Config{ReadToken: "r", OperatorToken: "o", AdminToken: "a"})
	for _, c := range []struct{ method, path string }{
		{"PUT", "/api/v1/map/pins"}, {"DELETE", "/api/v1/map/pins"},
		{"PUT", "/api/v1/devices/aa:bb:cc:00:00:01/label"}, {"PUT", "/api/v1/devices/aa:bb:cc:00:00:01/profile"}, {"POST", "/api/v1/devices/aa:bb:cc:00:00:01/link"},
		{"PATCH", "/api/v1/findings/1"}, {"POST", "/api/v1/findings/1/fine"}, {"POST", "/api/v1/findings/seen"},
		{"POST", "/api/v1/anomalies/mute"}, {"DELETE", "/api/v1/anomalies/mute"},
		{"POST", "/api/v1/annotations"}, {"DELETE", "/api/v1/annotations/1"},
		{"POST", "/api/v1/bookmarks"}, {"DELETE", "/api/v1/bookmarks/1"},
		{"POST", "/api/v1/incidents"}, {"PATCH", "/api/v1/incidents/1"}, {"DELETE", "/api/v1/incidents/1"}, {"POST", "/api/v1/incidents/1/pin"},
		{"POST", "/api/v1/notify/test"},
	} {
		if resp, body := do(t, srv, call{method: c.method, path: c.path, body: `{}`, token: "r"}); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s as a viewer: %d %s", c.method, c.path, resp.StatusCode, body)
		}
	}
	// And a viewer may still ask questions, which POST but change nothing.
	if resp, body := do(t, srv, call{method: "POST", path: "/api/v1/ask", body: `{"q":"any anomalies?"}`, token: "r"}); resp.StatusCode != 200 {
		t.Errorf("ask as a viewer: %d %s", resp.StatusCode, body)
	}
}

func sessionFrom(t *testing.T, resp *http.Response) *http.Cookie {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatalf("no cookie: %v", resp.Header)
	return nil
}

func TestSessions(t *testing.T) {
	srv, _, s := authServer(t, Config{ReadToken: "r", OperatorToken: "o", AdminToken: "a"})
	if resp, _ := do(t, srv, call{method: "POST", path: "/api/v1/session", body: `{"token":"wrong"}`}); resp.StatusCode != 401 {
		t.Errorf("a wrong token: %d", resp.StatusCode)
	}
	resp, _ := do(t, srv, call{method: "POST", path: "/api/v1/session", body: `{"token":"o"}`})
	c := sessionFrom(t, resp)
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie %+v", c)
	}
	if strings.Contains(c.Value, "o.") && !strings.HasPrefix(c.Value, "operator.") {
		t.Errorf("value %q", c.Value)
	}
	if resp, _ := do(t, srv, call{method: "POST", path: note, body: noteBody, cookie: c.Value}); resp.StatusCode != 200 {
		t.Errorf("writing with the cookie: %d", resp.StatusCode)
	}
	if resp, _ := do(t, srv, call{method: "GET", path: auditPath, cookie: c.Value}); resp.StatusCode != 403 {
		t.Errorf("an operator's cookie reading the audit log: %d", resp.StatusCode)
	}
	// A forged role, a bad signature, an expired one: nothing.
	parts := strings.Split(c.Value, ".")
	for _, forged := range []string{
		"admin." + parts[1] + "." + parts[2],
		parts[0] + "." + parts[1] + "." + strings.Repeat("0", 64),
		parts[0] + ".99999999999." + parts[2],
		"garbage", "", "a.b", "admin.x.y",
	} {
		if resp, _ := do(t, srv, call{method: "GET", path: readAPI, cookie: forged}); resp.StatusCode != 401 {
			t.Errorf("cookie %q: %d", forged, resp.StatusCode)
		}
	}
	if s.verifySession(c.Value, time.Now().Add(sessionLife+time.Hour)) != RoleNone {
		t.Error("an expired session still works")
	}
	// Changing the token ends the sessions it started.
	s.SetRoleTokens("o2", "a")
	if resp, _ := do(t, srv, call{method: "GET", path: readAPI, cookie: c.Value}); resp.StatusCode != 401 {
		t.Errorf("after the token changed: %d", resp.StatusCode)
	}
}

// A read token that did everything, demoted by adding an operator token, can't keep
// its old powers through an old cookie.
func TestDemotedTokenLosesItsSession(t *testing.T) {
	srv, _, s := authServer(t, Config{ReadToken: "r"})
	resp, _ := do(t, srv, call{method: "POST", path: "/api/v1/session", body: `{"token":"r"}`})
	c := sessionFrom(t, resp)
	if resp, _ := do(t, srv, call{method: "POST", path: note, body: noteBody, cookie: c.Value}); resp.StatusCode != 200 {
		t.Fatalf("before: %d", resp.StatusCode)
	}
	s.SetRoleTokens("o", "")
	if resp, _ := do(t, srv, call{method: "POST", path: note, body: noteBody, cookie: c.Value}); resp.StatusCode == 200 {
		t.Error("the old cookie can still write")
	}
}

// Another site's page can make a browser send a cookie. It can't make it say it came
// from here.
func TestCookiesDontWorkFromAnotherSite(t *testing.T) {
	srv, _, _ := authServer(t, Config{ReadToken: "r"})
	resp, _ := do(t, srv, call{method: "POST", path: "/api/v1/session", body: `{"token":"r"}`})
	cookie := sessionFrom(t, resp).Value
	evil := map[string]string{"Origin": "https://evil.example"}
	if resp, _ := do(t, srv, call{method: "POST", path: note, body: noteBody, cookie: cookie, headers: evil}); resp.StatusCode != 403 {
		t.Errorf("from another site: %d", resp.StatusCode)
	}
	if resp, _ := do(t, srv, call{method: "POST", path: "/api/v1/session", body: `{"token":"r"}`, headers: evil}); resp.StatusCode != 403 {
		t.Errorf("signing in from another site: %d", resp.StatusCode)
	}
	if resp, _ := do(t, srv, call{method: "POST", path: note, body: noteBody, cookie: cookie, headers: map[string]string{"Origin": srv.URL}}); resp.StatusCode != 200 {
		t.Errorf("from this site: %d", resp.StatusCode)
	}
	// A form can post without a preflight, as long as it isn't JSON.
	if resp, _ := do(t, srv, call{method: "POST", path: note, body: noteBody, cookie: cookie, headers: map[string]string{"Content-Type": "text/plain"}}); resp.StatusCode != 403 {
		t.Errorf("as text/plain: %d", resp.StatusCode)
	}
	// A bearer token isn't sent by a browser by itself, so it needs none of this.
	if resp, _ := do(t, srv, call{method: "POST", path: note, body: noteBody, token: "r", headers: evil}); resp.StatusCode != 200 {
		t.Errorf("a token: %d", resp.StatusCode)
	}
}

func TestProxyAuth(t *testing.T) {
	cfg := Config{ReadToken: "r", OperatorToken: "o", AdminToken: "a", Proxy: &ProxyAuth{
		Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		Roles:   map[string]Role{"alice": RoleAdmin, "bob": RoleOperator},
		Default: RoleViewer,
	}}
	srv, st, _ := authServer(t, cfg)
	as := func(user string) map[string]string { return map[string]string{"Remote-User": user} }
	for user, want := range map[string]int{"alice": 200, "bob": 403, "carol": 403} {
		if resp, _ := do(t, srv, call{method: "GET", path: auditPath, headers: as(user)}); resp.StatusCode != want {
			t.Errorf("%s: %d, want %d", user, resp.StatusCode, want)
		}
	}
	if resp, _ := do(t, srv, call{method: "POST", path: note, body: noteBody, headers: as("carol")}); resp.StatusCode != 403 {
		t.Errorf("a viewer wrote: %d", resp.StatusCode)
	}
	// Notes are signed with the name, whatever the page says.
	resp, body := do(t, srv, call{method: "POST", path: note, body: `{"ts":1000,"kind":"note","text":"x","author":"not bob"}`, headers: as("bob")})
	if resp.StatusCode != 200 || !strings.Contains(body, `"author":"bob"`) {
		t.Errorf("signed: %d %s", resp.StatusCode, body)
	}
	got, err := st.Audit(context.Background(), 10)
	if err != nil || len(got) != 1 || got[0].Actor != "bob" || got[0].Role != "operator" || got[0].Action != "POST /api/v1/annotations" {
		t.Errorf("audit: %+v, %v", got, err)
	}
	_, me := do(t, srv, call{method: "GET", path: "/api/v1/me", headers: as("alice")})
	if !strings.Contains(me, `"user":"alice"`) || !strings.Contains(me, `"role":"admin"`) || !strings.Contains(me, `"via":"proxy"`) {
		t.Errorf("me: %s", me)
	}
	// No name: the proxy let them through unauthenticated, and tokens still apply.
	if resp, _ := do(t, srv, call{method: "GET", path: readAPI}); resp.StatusCode != 401 {
		t.Errorf("no header, no token: %d", resp.StatusCode)
	}
	// A name with a line break in it isn't a name.
	r := httptest.NewRequest("GET", readAPI, nil)
	r.RemoteAddr = "127.0.0.1:5"
	r.Header["Remote-User"] = []string{"alice\nadmin"}
	if _, ok := New(Config{Store: st, ReadToken: "r", Proxy: cfg.Proxy}).proxyIdentity(r); ok {
		t.Error("a control character in a name was accepted")
	}
}

// From an untrusted address, the header is text anyone could send.
func TestProxyHeaderFromElsewhereIsIgnored(t *testing.T) {
	srv, _, s := authServer(t, Config{ReadToken: "r", Proxy: &ProxyAuth{
		Trusted: []netip.Prefix{netip.MustParsePrefix("10.9.9.0/24")},
		Roles:   map[string]Role{"alice": RoleAdmin},
	}})
	if resp, _ := do(t, srv, call{method: "GET", path: auditPath, headers: map[string]string{"Remote-User": "alice"}}); resp.StatusCode != 401 {
		t.Errorf("a spoofed header: %d", resp.StatusCode)
	}
	r := httptest.NewRequest("GET", readAPI, nil)
	r.Header.Set("Remote-User", "alice")
	r.Header.Set("X-Forwarded-For", "10.9.9.1")
	r.RemoteAddr = "192.168.1.5:1000"
	if _, ok := s.proxyIdentity(r); ok {
		t.Error("X-Forwarded-For made an address trusted")
	}
	r.RemoteAddr = "10.9.9.1:1000"
	if id, ok := s.proxyIdentity(r); !ok || id.User != "alice" {
		t.Errorf("from the proxy: %+v, %v", id, ok)
	}
	r.RemoteAddr = "[::ffff:10.9.9.1]:1000"
	if _, ok := s.proxyIdentity(r); !ok {
		t.Error("a v4-mapped proxy address isn't recognised")
	}
}

func TestChangesAreAudited(t *testing.T) {
	srv, st, _ := authServer(t, Config{ReadToken: "r", OperatorToken: "o", AdminToken: "a"})
	ctx := context.Background()
	if resp, _ := do(t, srv, call{method: "POST", path: note, body: noteBody, token: "o"}); resp.StatusCode != 200 {
		t.Fatalf("%d", resp.StatusCode)
	}
	// What failed changed nothing, and reading and asking aren't changes.
	do(t, srv, call{method: "POST", path: note, body: `not json`, token: "o"})
	do(t, srv, call{method: "POST", path: note, body: noteBody, token: "r"})
	do(t, srv, call{method: "GET", path: readAPI, token: "o"})
	do(t, srv, call{method: "POST", path: "/api/v1/ask", body: `{"q":"hello"}`, token: "o"})
	do(t, srv, call{method: "PUT", path: "/api/v1/devices/aa:bb:cc:00:00:99/label", body: `{"label":"x"}`, token: "o"})
	got, err := st.Audit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Actor != "token" || got[0].Role != "operator" {
		t.Errorf("audit: %+v", got)
	}
	_, list := do(t, srv, call{method: "GET", path: auditPath, token: "a"})
	if !strings.Contains(list, "POST /api/v1/annotations") {
		t.Errorf("list: %s", list)
	}
}

func TestSensorSettingsRoles(t *testing.T) {
	srv, _, _ := authServer(t, Config{IngestToken: "ingest", ReadToken: "read", OperatorToken: "operator"})
	put := func(token, path, body string) int {
		resp, _ := do(t, srv, call{method: "PUT", path: path, body: body, token: token})
		return resp.StatusCode
	}
	if got := put("read", "/api/v1/sensors/edge/config", `{"flush_s":3}`); got != http.StatusForbidden {
		t.Errorf("a viewer changed settings: %d", got)
	}
	if got := put("operator", "/api/v1/sensors/edge/config", `{"flush_s":3000}`); got != http.StatusBadRequest {
		t.Errorf("out of range: %d", got)
	}
	if got := put("operator", "/api/v1/sensors/edge/config", `{"flushs":3}`); got != http.StatusBadRequest {
		t.Errorf("a typo read as saved: %d", got)
	}
	if got := put("operator", "/api/v1/sensors/edge/config", `{"flush_s":3}`); got != http.StatusNoContent {
		t.Errorf("%d", got)
	}
	if got := put("operator", "/api/v1/sensors/%2A/config", `{"log_level":"warn"}`); got != http.StatusNoContent {
		t.Errorf("fleet: %d", got)
	}
	// A sensor asks with the ingest token, and gets both layers.
	sensor := map[string]string{wire.HeaderSensor: "edge"}
	resp, body := do(t, srv, call{method: "GET", path: "/api/v1/sensor/config", token: "ingest", headers: sensor})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"flush_s":3`) || !strings.Contains(body, `"log_level":"warn"`) {
		t.Errorf("%d %s", resp.StatusCode, body)
	}
	if resp, _ := do(t, srv, call{method: "GET", path: "/api/v1/sensor/config", token: "read", headers: sensor}); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the read token got a sensor's settings: %d", resp.StatusCode)
	}
	if resp, _ := do(t, srv, call{method: "GET", path: "/api/v1/sensor/config", token: "ingest"}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("no sensor named: %d", resp.StatusCode)
	}
}
