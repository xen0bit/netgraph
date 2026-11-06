package agent

import (
	"context"
	"fmt"
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
	Logf     func(string, ...any)
}

// Run registers, then scans and uploads until ctx ends.
func (r *Runner) Run(ctx context.Context) error {
	if r.Client == nil || r.Scanner == nil {
		return fmt.Errorf("agent needs a client and scanner")
	}
	if r.Interval <= 0 {
		r.Interval = 10 * time.Second
	}
	if r.Logf == nil {
		r.Logf = func(string, ...any) {}
	}
	hello := &Hello{Name: r.Client.Agent, OS: "linux", Started: time.Now().UnixMilli()}
	if r.Enforcer != nil {
		hello.Capabilities = append(hello.Capabilities, "enforce")
	}
	hello.Capabilities = append(hello.Capabilities, "process-identity", "proc-sockets")
	if err := r.Client.Hello(ctx, hello); err != nil {
		return err
	}
	var lastPolicy *PolicyResponse
	last := map[string]Connection{}
	tick := time.NewTicker(r.Interval)
	defer tick.Stop()
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
		actuals := make([]Actual, 0)
		for i := range conns {
			if lastPolicy != nil && lastPolicy.Policy != nil {
				conns[i].Predicted, conns[i].Rule, conns[i].Reason = predict(lastPolicy, conns[i])
			}
			if conns[i].Actual == "" {
				conns[i].Actual = "none"
			}
		}
		if r.Enforcer != nil {
			got, err := r.Enforcer.Apply(ctx, conns)
			if err != nil {
				r.Logf("enforce: %v", err)
			} else {
				actuals = append(actuals, got...)
				for _, a := range got {
					for i := range conns {
						if conns[i].Key == a.Key {
							conns[i].Actual = a.Action
							conns[i].Stalled = a.Stalled
						}
					}
				}
			}
		}
		changed := make([]Connection, 0, len(conns))
		for _, c := range conns {
			old, ok := last[c.Key]
			if !ok || old.Predicted != c.Predicted || old.Actual != c.Actual || old.State != c.State || old.Stalled != c.Stalled {
				changed = append(changed, c)
			}
		}
		last = make(map[string]Connection, len(conns))
		for _, c := range conns {
			last[c.Key] = c
		}
		if err := r.Client.Send(ctx, &Batch{Processes: procs, Connections: changed, Actuals: actuals}); err != nil {
			r.Logf("send: %v", err)
		}
		if !sleep(ctx, r.Interval) {
			return ctx.Err()
		}
	}
}

func predict(p *PolicyResponse, c Connection) (action, rule, reason string) {
	if p == nil || p.Policy == nil {
		return "none", "", "no active policy"
	}
	d := p.Policy.Evaluate(policy.Conn{
		Direction: c.Direction, Profile: p.Profile, Name: first(c.SNI, c.HTTPHost), Host: c.HTTPHost,
		IP: c.RemoteIP, Port: strconv.Itoa(c.RemotePort), Proto: c.Proto, Process: c.App,
	})
	return d.Action, d.Rule, d.Reason
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

// LocalZone is a placeholder for a future agent network-context integration.
// Rules that select only by process or app match without it.
const LocalZone = ""

// Once registers and performs one scan/upload, for -once and tests.
func (r *Runner) Once(ctx context.Context) error {
	if r.Client == nil || r.Scanner == nil {
		return fmt.Errorf("agent needs a client and scanner")
	}
	hello := &Hello{Name: r.Client.Agent, OS: "linux", Started: time.Now().UnixMilli()}
	if r.Enforcer != nil {
		hello.Capabilities = append(hello.Capabilities, "enforce")
	}
	hello.Capabilities = append(hello.Capabilities, "process-identity", "proc-sockets")
	if err := r.Client.Hello(ctx, hello); err != nil {
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
		conns[i].Predicted, conns[i].Rule, conns[i].Reason = predict(pol, conns[i])
		conns[i].Actual = "none"
	}
	var actuals []Actual
	if r.Enforcer != nil {
		actuals, err = r.Enforcer.Apply(ctx, conns)
		if err != nil {
			return err
		}
		for _, a := range actuals {
			for i := range conns {
				if conns[i].Key == a.Key {
					conns[i].Actual, conns[i].Stalled = a.Action, a.Stalled
				}
			}
		}
	}
	return r.Client.Send(ctx, &Batch{Processes: procs, Connections: conns, Actuals: actuals})
}
