// Package agent defines the contract between netgraph's optional host agent
// and the server. The agent is separate from netgraph-sensor: it identifies
// local processes, predicts policy decisions, and may enforce them, while the
// sensor remains a small passive router capture agent.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/xen0bit/netgraph/internal/policy"
)

// Version is the agent protocol version. Fields are only ever added.
const Version = 1

// Hello identifies one agent process.
type Hello struct {
	Name         string   `json:"name"`
	Host         string   `json:"host,omitempty"`
	OS           string   `json:"os,omitempty"`
	Arch         string   `json:"arch,omitempty"`
	Version      string   `json:"version,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Started      int64    `json:"started,omitempty"`
	PIDs         int      `json:"pids,omitempty"`
}

// Process is a local process the agent observed.
type Process struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid,omitempty"`
	UID     int    `json:"uid,omitempty"`
	Path    string `json:"path,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`
	CodeID  string `json:"code_id,omitempty"` // sha256:... for now
	SHA256  string `json:"sha256,omitempty"`
	Signer  string `json:"signer,omitempty"`
	Package string `json:"package,omitempty"`
	Start   int64  `json:"start,omitempty"`
}

// Connection is one local socket with process attribution. Key is stable for
// the same 5-tuple within one agent boot.
type Connection struct {
	Key        string `json:"key"`
	Proto      string `json:"proto,omitempty"`
	LocalIP    string `json:"local_ip,omitempty"`
	LocalPort  int    `json:"local_port,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	Direction  string `json:"direction,omitempty"` // out, in, local
	State      string `json:"state,omitempty"`
	PID        int    `json:"pid,omitempty"`
	UID        int    `json:"uid,omitempty"`
	App        string `json:"app,omitempty"`
	Path       string `json:"path,omitempty"`
	CodeID     string `json:"code_id,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	BytesOut   uint64 `json:"bytes_out,omitempty"`
	BytesIn    uint64 `json:"bytes_in,omitempty"`
	FirstSeen  int64  `json:"first_seen,omitempty"`
	LastSeen   int64  `json:"last_seen,omitempty"`
	SNI        string `json:"sni,omitempty"`
	HTTPHost   string `json:"http_host,omitempty"`
	Predicted  string `json:"predicted,omitempty"` // allow, deny, ask
	// Scope says what decided Predicted: host (a rule for every program on
	// this host), process (a rule for one program) or default (no rule).
	Scope   string `json:"scope,omitempty"`
	Actual  string `json:"actual,omitempty"` // deny when the agent dropped it, else none
	Rule    string `json:"rule,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Stalled bool   `json:"stalled,omitempty"`
}

// Scopes of a prediction.
const (
	ScopeHost    = "host"
	ScopeProcess = "process"
	ScopeDefault = "default"
)

// Actual is an enforcement result the agent reports back.
type Actual struct {
	Key     string `json:"key"`
	Action  string `json:"action"` // allow, deny, ask, none
	Rule    string `json:"rule,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Stalled bool   `json:"stalled,omitempty"`
	At      int64  `json:"at,omitempty"`
}

// Batch is one agent upload.
type Batch struct {
	Version     int          `json:"version"`
	Agent       string       `json:"agent"`
	Boot        string       `json:"boot"`
	Seq         uint64       `json:"seq"`
	Sent        int64        `json:"sent"`
	Hello       *Hello       `json:"hello,omitempty"`
	Processes   []Process    `json:"processes,omitempty"`
	Connections []Connection `json:"connections,omitempty"`
	Actuals     []Actual     `json:"actuals,omitempty"`
}

// PolicyResponse is what the server tells an agent to enforce or predict.
type PolicyResponse struct {
	Policy  *policy.Policy `json:"policy"`
	Profile string         `json:"profile,omitempty"`
	Mode    string         `json:"mode,omitempty"`
	Hash    string         `json:"hash,omitempty"`
}

// Client talks to the server with the agent token.
type Client struct {
	Base   string
	Token  string
	HTTP   *http.Client
	Agent  string
	Boot   string
	Seq    uint64
	OnSent func(seq uint64, bytes int)
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) do(ctx context.Context, method, path string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, body)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("server: %d %s", resp.StatusCode, bytes.TrimSpace(out))
	}
	return out, nil
}

// Hello registers the agent.
func (c *Client) Hello(ctx context.Context, h *Hello) error {
	_, err := c.do(ctx, http.MethodPost, "/api/v1/agent/hello", h)
	return err
}

// Send uploads one batch, assigning its seq.
func (c *Client) Send(ctx context.Context, b *Batch) error {
	c.Seq++
	b.Version, b.Agent, b.Boot, b.Seq = Version, c.Agent, c.Boot, c.Seq
	if b.Sent == 0 {
		b.Sent = time.Now().UnixMilli()
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	if _, err := c.do(ctx, http.MethodPost, "/api/v1/agent/events", b); err != nil {
		return err
	}
	if c.OnSent != nil {
		c.OnSent(b.Seq, len(raw))
	}
	return nil
}

// Policy fetches the active policy and profile mode.
func (c *Client) Policy(ctx context.Context) (*PolicyResponse, error) {
	out, err := c.do(ctx, http.MethodGet, "/api/v1/agent/policy", nil)
	if err != nil {
		return nil, err
	}
	var p PolicyResponse
	if err := json.Unmarshal(out, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Report sends enforcement results.
func (c *Client) Report(ctx context.Context, actuals []Actual) error {
	if len(actuals) == 0 {
		return nil
	}
	b := &Batch{Actuals: actuals}
	return c.Send(ctx, b)
}
