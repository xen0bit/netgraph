package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/xen0bit/netgraph/internal/model"
)

// Role is what someone may do. Each includes those before it.
type Role int

// Roles.
const (
	RoleNone     Role = iota
	RoleViewer        // reads
	RoleOperator      // and labels, notes, findings, incidents, the map
	RoleAdmin         // and the audit log, and sending test notifications
)

func (r Role) String() string {
	return map[Role]string{RoleViewer: "viewer", RoleOperator: "operator", RoleAdmin: "admin"}[r]
}

// ParseRole reads a role's name.
func ParseRole(s string) (Role, bool) {
	switch s {
	case "viewer":
		return RoleViewer, true
	case "operator":
		return RoleOperator, true
	case "admin":
		return RoleAdmin, true
	}
	return RoleNone, false
}

// ProxyAuth trusts a reverse proxy to say who someone is. The header counts only
// from these addresses: from anywhere else it's just text anyone could send.
type ProxyAuth struct {
	Trusted []netip.Prefix
	Header  string          // default Remote-User
	Roles   map[string]Role // by user, case-sensitive
	Default Role            // for a user not listed; default viewer
}

// Identity is who a request is from.
type Identity struct {
	User string `json:"user,omitempty"` // a name, from a trusted proxy
	Role Role   `json:"-"`
	Via  string `json:"via"` // proxy, token, session or open
}

// Actor is how the audit log names them.
func (i Identity) Actor() string {
	if i.User != "" {
		return i.User
	}
	return i.Via
}

type roleTokens struct{ operator, admin string }

type identityKey struct{}

func identityOf(ctx context.Context) Identity {
	id, _ := ctx.Value(identityKey{}).(Identity)
	return id
}

// SetRoleTokens replaces the operator and admin tokens, such as on a SIGHUP.
func (s *Server) SetRoleTokens(operator, admin string) {
	s.roleTok.Store(&roleTokens{operator, admin})
}

func (s *Server) roleTokens() roleTokens {
	if p := s.roleTok.Load(); p != nil {
		return *p
	}
	return roleTokens{}
}

// tokenRoles lists every token and what it grants. Until a server has an operator or
// admin token, nothing has separated reading from writing: the read token does
// everything, as it always did, so an upgrade changes nothing until someone asks.
func (s *Server) tokenRoles() []struct {
	token string
	role  Role
} {
	rt, read := s.roleTokens(), s.readToken()
	type pair = struct {
		token string
		role  Role
	}
	var out []pair
	switch {
	case rt.operator == "" && rt.admin == "":
		if read != "" {
			out = append(out, pair{read, RoleAdmin})
		}
	default:
		if read != "" {
			out = append(out, pair{read, RoleViewer})
		}
		if rt.admin != "" {
			out = append(out, pair{rt.admin, RoleAdmin})
		}
		if rt.operator != "" {
			// With no admin token, the operator token is the highest there is.
			role := RoleOperator
			if rt.admin == "" {
				role = RoleAdmin
			}
			out = append(out, pair{rt.operator, role})
		}
	}
	return out
}

func (s *Server) roleOfToken(tok string) Role {
	best := RoleNone
	if tok == "" {
		return best
	}
	// Every comparison runs, whichever matches.
	for _, p := range s.tokenRoles() {
		if subtle.ConstantTimeCompare([]byte(tok), []byte(p.token)) == 1 && p.role > best {
			best = p.role
		}
	}
	return best
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if got, ok := strings.CutPrefix(h, "Bearer "); ok {
		return got
	}
	return ""
}

// identify says who a request is from, if anyone it knows. Credentials are tried
// strongest statement first, and one that's wrong isn't rescued by another.
func (s *Server) identify(r *http.Request, allowQuery bool) (Identity, bool) {
	if id, ok := s.proxyIdentity(r); ok {
		return id, true
	}
	if tok := bearer(r); tok != "" {
		role := s.roleOfToken(tok)
		if role != RoleNone {
			return Identity{Role: role, Via: "token"}, true
		}
		// A wrong token where reading needs one is refused. Where reading is open, it's
		// only someone's stale token, and it was never checked: it earns nothing, and
		// costs nothing.
		if s.readToken() != "" {
			return Identity{}, false
		}
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		if role := s.verifySession(c.Value, s.now()); role != RoleNone {
			return Identity{Role: role, Via: "session"}, true
		}
	}
	if allowQuery {
		if tok := r.URL.Query().Get("token"); tok != "" {
			role := s.roleOfToken(tok)
			return Identity{Role: role, Via: "token"}, role != RoleNone
		}
	}
	// Nothing presented. With no read token, reading is open, as ever; and with no
	// credentials set up at all, so is everything else.
	if s.readToken() != "" {
		return Identity{}, false
	}
	rt := s.roleTokens()
	if rt.operator == "" && rt.admin == "" && len(s.proxyAuth().Trusted) == 0 {
		return Identity{Role: RoleAdmin, Via: "open"}, true
	}
	return Identity{Role: RoleViewer, Via: "open"}, true
}

func (s *Server) proxyAuth() *ProxyAuth {
	if s.cfg.Proxy != nil {
		return s.cfg.Proxy
	}
	return &ProxyAuth{}
}

func (s *Server) proxyIdentity(r *http.Request) (Identity, bool) {
	p := s.proxyAuth()
	if len(p.Trusted) == 0 {
		return Identity{}, false
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return Identity{}, false
	}
	addr := ap.Addr().Unmap()
	trusted := false
	for _, pre := range p.Trusted {
		if pre.Contains(addr) {
			trusted = true
			break
		}
	}
	if !trusted {
		return Identity{}, false
	}
	header := p.Header
	if header == "" {
		header = "Remote-User"
	}
	user := r.Header.Get(header)
	if user == "" || len(user) > 256 || strings.IndexFunc(user, unicode.IsControl) >= 0 {
		return Identity{}, false
	}
	role, ok := p.Roles[user]
	if !ok {
		role = p.Default
		if role == RoleNone {
			role = RoleViewer
		}
	}
	return Identity{User: user, Role: role, Via: "proxy"}, true
}

func (s *Server) now() time.Time { return s.cfg.Store.Now() }

// require is the gate on every route but ingest. Anything that changes something is
// recorded, once it has succeeded.
func (s *Server) require(min Role, h http.HandlerFunc) http.Handler {
	return s.gate(min, false, h)
}

func (s *Server) gate(min Role, allowQuery bool, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.identify(r, allowQuery)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="netgraph"`)
			httpError(w, http.StatusUnauthorized, errors.New("missing or wrong read token"))
			return
		}
		if id.Role < min {
			httpError(w, http.StatusForbidden, fmt.Errorf("your role is %s; this needs %s", id.Role, min))
			return
		}
		safe := r.Method == http.MethodGet || r.Method == http.MethodHead
		// A browser sends a cookie by itself, a bearer token never: requests carrying
		// only the former have to show they came from our own page. A proxy's login
		// is a cookie too, one we can't see.
		if !safe && (id.Via == "session" || id.Via == "proxy") {
			if err := sameOrigin(r); err != nil {
				httpError(w, http.StatusForbidden, err)
				return
			}
		}
		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, id))
		if safe || !isChange(r) {
			h(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h(rec, r)
		if rec.status < 400 {
			s.audit(r, id)
			s.memo.changed()
			if affectsDNS(r.Pattern) {
				s.dnsChanged()
			}
		}
	})
}

// affectsDNS says whether a change can alter what the DNS server answers: a
// blocklist, a group of them, a device's groups, a restored bundle. (Its own
// rules' routes tell it themselves.)
func affectsDNS(pattern string) bool {
	for _, p := range []string{"/blocklists", "/rule-groups", "/profile", "/policy/bundle"} {
		if strings.Contains(pattern, p) {
			return true
		}
	}
	return false
}

// isChange: these POST to ask something, and change nothing.
func isChange(r *http.Request) bool {
	switch r.Pattern {
	case "POST /api/v1/ask", "POST /api/v1/whatif", "POST /api/v1/policy/explain", "POST /api/v1/policy/export":
		return false
	}
	return true
}

func (s *Server) audit(r *http.Request, id Identity) {
	var target []string
	for _, k := range []string{"mac", "id"} {
		if v := r.PathValue(k); v != "" {
			target = append(target, v)
		}
	}
	e := model.AuditEntry{Actor: id.Actor(), Role: id.Role.String(), Action: r.Pattern, Target: strings.Join(target, " "), Remote: r.RemoteAddr}
	// Not the request's context: the change happened, whether or not the client's
	// still there to hear about it.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if err := s.cfg.Store.AddAudit(ctx, e); err != nil {
		s.log.Error("audit log", "err", err, "action", e.Action)
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusRecorder) WriteHeader(code int) {
	if !w.wrote {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(b)
}

func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// sameOrigin refuses a state change another site's page could have caused: SameSite
// keeps our cookie off those requests in current browsers, and this holds for a
// proxy's cookie, whose attributes aren't ours. A browser always sends Origin on one;
// tools with a cookie don't, and aren't the threat.
func sameOrigin(r *http.Request) error {
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			return errors.New("this request came from another site")
		}
	}
	if r.Method != http.MethodDelete && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return errors.New("expected application/json")
	}
	return nil
}

// --- sessions -------------------------------------------------------------------------

const (
	sessionCookie = "netgraph_session"
	sessionLife   = 30 * 24 * time.Hour
)

// A session is a signed note of a role and an expiry, keyed by the token that earned
// it: nothing to store, and changing a token ends every session it started.
func sessionMAC(token string, role Role, exp int64) string {
	m := hmac.New(sha256.New, []byte("netgraph-session-v1\x00"+token))
	fmt.Fprintf(m, "%s|%d", role, exp)
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Server) signSession(token string, role Role, now time.Time) (string, time.Time) {
	exp := now.Add(sessionLife)
	return fmt.Sprintf("%s.%d.%s", role, exp.Unix(), sessionMAC(token, role, exp.Unix())), exp
}

func (s *Server) verifySession(v string, now time.Time) Role {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return RoleNone
	}
	role, ok := ParseRole(parts[0])
	if !ok {
		return RoleNone
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || now.Unix() >= exp {
		return RoleNone
	}
	for _, p := range s.tokenRoles() {
		// The role it grants today: a read token demoted by adding an operator token
		// can't keep its old powers through an old cookie.
		if p.role == role && hmac.Equal([]byte(parts[2]), []byte(sessionMAC(p.token, role, exp))) {
			return role
		}
	}
	return RoleNone
}

// createSession trades a token for a cookie that scripts can't read, so the token
// doesn't have to sit in localStorage.
func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	if err := sameOrigin(r); err != nil {
		httpError(w, http.StatusForbidden, err)
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body.Token == "" {
		httpError(w, http.StatusBadRequest, errors.New(`expected {"token": "..."}`))
		return
	}
	role := s.roleOfToken(body.Token)
	if role == RoleNone {
		httpError(w, http.StatusUnauthorized, errors.New("wrong token"))
		return
	}
	value, exp := s.signSession(body.Token, role, s.now())
	http.SetCookie(w, s.cookie(r, value, exp))
	writeJSON(w, map[string]string{"role": role.String()})
}

func (s *Server) cookie(r *http.Request, value string, exp time.Time) *http.Cookie {
	return &http.Cookie{Name: sessionCookie, Value: value, Path: "/", Expires: exp, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: viaHTTPS(r)}
}

// viaHTTPS: directly, or behind TLS at a proxy, where the browser's Origin still says
// https. Origin can't be set by a page.
func viaHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.HasPrefix(r.Header.Get("Origin"), "https://")
}

// endSession forgets the cookie. It's the browser that forgets: the signed note stays
// valid until it expires or its token changes, for anyone who copied it.
func (s *Server) endSession(w http.ResponseWriter, r *http.Request) {
	if err := sameOrigin(r); err != nil {
		httpError(w, http.StatusForbidden, err)
		return
	}
	c := s.cookie(r, "", time.Unix(0, 0))
	c.MaxAge = -1
	http.SetCookie(w, c)
	w.WriteHeader(http.StatusNoContent)
}

// me says who the page is talking as, so it can say so.
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r.Context())
	writeJSON(w, map[string]any{"user": id.User, "role": id.Role.String(), "via": id.Via})
}

func (s *Server) auditLog(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	out, err := s.cfg.Store.Audit(r.Context(), n)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

// author is who wrote something: a proxy's word for it beats what the page claims.
func author(r *http.Request, given string) string {
	if id := identityOf(r.Context()); id.User != "" {
		return id.User
	}
	return given
}

// SetAgentToken replaces the host-agent token, such as on SIGHUP.
func (s *Server) SetAgentToken(tok string) { s.agentTok.Store(&tok) }

func (s *Server) agentToken() string {
	if p := s.agentTok.Load(); p != nil {
		return *p
	}
	return ""
}

// requireAgent accepts only the dedicated agent token. An empty token means
// the agent surface is off, not open.
func (s *Server) requireAgent(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := s.agentToken()
		if want == "" {
			httpError(w, http.StatusForbidden, errors.New("host agent is not configured"))
			return
		}
		if subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(want)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="netgraph-agent"`)
			httpError(w, http.StatusUnauthorized, errors.New("missing or wrong agent token"))
			return
		}
		h(w, r)
	})
}
