package agent

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"strconv"
	"time"

	"github.com/xen0bit/netgraph/internal/policy"
)

// Scanner is the platform-specific process/connection source.
type Scanner interface {
	Scan(context.Context) ([]Process, []Connection, error)
}

// Enforcer applies predicted decisions. Nil means observe only.
type Enforcer interface {
	Apply(context.Context, []Connection) ([]Actual, error)
	Close() error
}

// Runner is the agent's main loop.
type Runner struct {
	Client   *Client
	Scanner  Scanner
	Enforcer Enforcer
	Interval time.Duration
	// Refresh is how often a connection that hasn't changed is sent again,
	// so the server knows it's still open (default a minute). The server
	// matches the agent's sockets to the sensor's connections by time.
	Refresh time.Duration
	// Hello describes this host; Run fills in what is left empty.
	Hello Hello
	Logf  func(string, ...any)
}

func (r *Runner) defaults() {
	if r.Interval <= 0 {
		r.Interval = 10 * time.Second
	}
	if r.Refresh <= 0 {
		r.Refresh = time.Minute
	}
	if r.Refresh < r.Interval {
		r.Refresh = r.Interval
	}
	if r.Logf == nil {
		r.Logf = func(string, ...any) {}
	}
}

// hello registers the agent, saying what it can do.
func (r *Runner) hello(ctx context.Context) error {
	h := r.Hello
	h.Name = r.Client.Agent
	if h.OS == "" {
		h.OS = runtime.GOOS
	}
	if h.Arch == "" {
		h.Arch = runtime.GOARCH
	}
	h.Started = time.Now().UnixMilli()
	h.Capabilities = slices.Clone(h.Capabilities)
	if c, ok := r.Scanner.(interface{ Capabilities() []string }); ok {
		h.Capabilities = append(h.Capabilities, c.Capabilities()...)
	}
	if r.Enforcer != nil {
		h.Capabilities = append(h.Capabilities, "enforce")
	}
	return r.Client.Hello(ctx, &h)
}

// Run registers, then scans and uploads until ctx ends.
func (r *Runner) Run(ctx context.Context) error {
	if r.Client == nil || r.Scanner == nil {
		return fmt.Errorf("agent needs a client and scanner")
	}
	r.defaults()
	if r.Enforcer != nil {
		defer r.Enforcer.Close()
	}
	// Retry registration: an agent started before its server keeps trying.
	for {
		err := r.hello(ctx)
		if err == nil {
			break
		}
		r.Logf("register: %v", err)
		if !sleep(ctx, r.Interval) {
			return ctx.Err()
		}
	}
	var lastPolicy *PolicyResponse
	type sent struct {
		c  Connection
		at time.Time
	}
	last := map[string]sent{}
	type sentProc struct {
		p  Process
		at time.Time
	}
	lastProcs := map[int]sentProc{}
	var lastSend time.Time
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		pol, err := r.Client.Policy(ctx)
		if err != nil {
			r.Logf("fetch policy: %v", err)
		} else {
			lastPolicy = pol
		}
		procs, conns, err := r.Scanner.Scan(ctx)
		if err != nil {
			r.Logf("scan: %v", err)
			if !sleep(ctx, r.Interval) {
				return ctx.Err()
			}
			continue
		}
		for i := range conns {
			conns[i].Predicted, conns[i].Scope, conns[i].Rule, conns[i].Reason = predict(lastPolicy, conns[i])
			if conns[i].Actual == "" {
				conns[i].Actual = "none"
			}
		}
		var got []Actual
		if r.Enforcer != nil {
			var err error
			got, err = r.Enforcer.Apply(ctx, conns)
			if err != nil {
				r.Logf("enforce: %v", err)
			}
			applyActuals(conns, got)
		}
		// Send what changed, and what hasn't been sent for a while: an open
		// connection's last_seen has to keep moving.
		now := time.Now()
		changed := make([]Connection, 0, len(conns))
		changedKeys := map[string]bool{}
		for _, c := range conns {
			old, ok := last[c.Key]
			if !ok || old.c.Predicted != c.Predicted || old.c.Actual != c.Actual || old.c.State != c.State ||
				old.c.Stalled != c.Stalled || now.Sub(old.at) >= r.Refresh {
				changed = append(changed, c)
				changedKeys[c.Key] = true
			}
		}
		actuals := make([]Actual, 0)
		for _, a := range got {
			if changedKeys[a.Key] {
				actuals = append(actuals, a)
			}
		}
		// Processes likewise: a new or changed one, and each again every
		// refresh, not the same list every scan.
		newProcs := make([]Process, 0, len(procs))
		for _, p := range procs {
			if old, ok := lastProcs[p.PID]; !ok || old.p != p || now.Sub(old.at) >= r.Refresh {
				newProcs = append(newProcs, p)
			}
		}
		sentOK := true
		if len(changed) > 0 || len(newProcs) > 0 || len(actuals) > 0 || now.Sub(lastSend) >= r.Refresh {
			if err := r.Client.Send(ctx, &Batch{Processes: newProcs, Connections: changed, Actuals: actuals}); err != nil {
				r.Logf("send: %v", err)
				// Nothing was recorded: send it all again next time.
				changedKeys = map[string]bool{}
				sentOK = false
			} else {
				lastSend = now
			}
		}
		if sentOK {
			for _, p := range newProcs {
				lastProcs[p.PID] = sentProc{p, now}
			}
		}
		seenProcs := make(map[int]bool, len(procs))
		for _, p := range procs {
			seenProcs[p.PID] = true
		}
		for pid := range lastProcs {
			if !seenProcs[pid] {
				delete(lastProcs, pid)
			}
		}
		next := make(map[string]sent, len(conns))
		for _, c := range conns {
			if changedKeys[c.Key] {
				next[c.Key] = sent{c, now}
			} else if old, ok := last[c.Key]; ok {
				next[c.Key] = old
			}
		}
		last = next
		if !sleep(ctx, r.Interval) {
			return ctx.Err()
		}
	}
}

// predict evaluates the server's policy for one connection, and says whether
// the decision came from a rule for the whole host, one for a program, or the
// default. Only the first can be enforced by address.
func predict(p *PolicyResponse, c Connection) (action, scope, rule, reason string) {
	if p == nil || p.Policy == nil {
		return "none", ScopeDefault, "", "no active policy"
	}
	d := p.Policy.Evaluate(policy.Conn{
		Direction: c.Direction, Profile: p.Profile, Name: first(c.SNI, c.HTTPHost), Host: c.HTTPHost,
		IP: c.RemoteIP, Port: strconv.Itoa(c.RemotePort), Proto: BaseProto(c.Proto), Process: c.App,
	})
	scope = ScopeDefault
	if d.Matched {
		scope = ScopeHost
		for _, r := range p.Policy.RulesV2 {
			if r.ID == d.RuleID && d.RuleID != "" {
				if (r.Local.Type != "" && r.Local.Type != "any") || (r.Via.Type != "" && r.Via.Type != "any") {
					scope = ScopeProcess
				}
				break
			}
		}
		if p.Policy.Version != 2 {
			scope = ScopeProcess // version 1 rules select zones of devices, not this host
		}
	}
	return d.Action, scope, d.Rule, d.Reason
}

// applyActuals records what the enforcer did on each connection.
func applyActuals(conns []Connection, actuals []Actual) {
	at := make(map[string]int, len(conns))
	for i := range conns {
		at[conns[i].Key] = i
	}
	for _, a := range actuals {
		if i, ok := at[a.Key]; ok {
			conns[i].Actual, conns[i].Stalled = a.Action, a.Stalled
		}
	}
}

func first(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Once registers and performs one scan/upload, for -once and tests.
func (r *Runner) Once(ctx context.Context) error {
	if r.Client == nil || r.Scanner == nil {
		return fmt.Errorf("agent needs a client and scanner")
	}
	r.defaults()
	if err := r.hello(ctx); err != nil {
		return err
	}
	pol, err := r.Client.Policy(ctx)
	if err != nil {
		return err
	}
	procs, conns, err := r.Scanner.Scan(ctx)
	if err != nil {
		return err
	}
	for i := range conns {
		conns[i].Predicted, conns[i].Scope, conns[i].Rule, conns[i].Reason = predict(pol, conns[i])
		conns[i].Actual = "none"
	}
	var actuals []Actual
	if r.Enforcer != nil {
		actuals, err = r.Enforcer.Apply(ctx, conns)
		applyActuals(conns, actuals)
		if err != nil {
			return err
		}
	}
	return r.Client.Send(ctx, &Batch{Processes: procs, Connections: conns, Actuals: actuals})
}
