package alert

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
)

// Channel delivers one message somewhere. Name identifies it to a person, and holds
// no secret: it's what the logs and the UI show.
type Channel interface {
	Name() string
	Send(ctx context.Context, p Payload) error
}

// Route is a channel with what should reach it.
type Route struct {
	Channel
	Min   string   // least severity of a finding; empty is any
	Kinds []string // finding kinds; empty is all
	Quiet *Quiet   // hours when only high severity goes through
}

// Quiet is a daily stretch of hours, possibly over midnight, in the server's time.
type Quiet struct {
	FromMin, ToMin int // minutes after midnight
}

// In reports whether t falls in the stretch.
func (q *Quiet) In(t time.Time) bool {
	m := t.Hour()*60 + t.Minute()
	if q.FromMin <= q.ToMin {
		return m >= q.FromMin && m < q.ToMin
	}
	return m >= q.FromMin || m < q.ToMin
}

func (q *Quiet) String() string {
	return fmt.Sprintf("%02d:%02d-%02d:%02d", q.FromMin/60, q.FromMin%60, q.ToMin/60, q.ToMin%60)
}

func parseQuiet(s string) (*Quiet, error) {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return nil, fmt.Errorf("quiet %q: want 22:00-07:00", s)
	}
	clock := func(v string) (int, error) {
		t, err := time.Parse("15:04", strings.TrimSpace(v))
		if err != nil {
			return 0, fmt.Errorf("quiet %q: want 22:00-07:00", s)
		}
		return t.Hour()*60 + t.Minute(), nil
	}
	from, err := clock(a)
	if err != nil {
		return nil, err
	}
	to, err := clock(b)
	if err != nil {
		return nil, err
	}
	if from == to {
		return nil, fmt.Errorf("quiet %q: it starts when it ends", s)
	}
	return &Quiet{from, to}, nil
}

// ParseChannel reads a channel from its URL. The URL holds its secrets, so an error
// here never repeats it.
//
//	https://example.com/hook         a webhook, as -alert-webhook
//	ntfy://host/topic?token=T        ntfy (ntfy+http:// for no TLS)
//	gotify://host/?token=T           Gotify (gotify+http:// for no TLS)
//	telegram://BOT:TOKEN@CHAT_ID     a Telegram bot
//	smtp://u:p@host:587/?from=a&to=b email (smtps:// for TLS from the start)
//
// Any of them take min=high, kinds=scan,rogue_dhcp and quiet=22:00-07:00.
func ParseChannel(raw string, client *http.Client) (Route, error) {
	var r Route
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" {
		return r, errors.New("not a URL") // url's error repeats the address, secrets and all
	}
	q := u.Query()
	if v := q.Get("min"); v != "" {
		if model.SeverityRank(v) == 0 {
			return r, errors.New("min is low, medium or high")
		}
		r.Min = v
	}
	if v := q.Get("kinds"); v != "" {
		for _, k := range strings.Split(v, ",") {
			if k = strings.TrimSpace(k); k != "" {
				r.Kinds = append(r.Kinds, k)
			}
		}
	}
	if v := q.Get("quiet"); v != "" {
		if r.Quiet, err = parseQuiet(v); err != nil {
			return r, err
		}
	}
	q.Del("min")
	q.Del("kinds")
	q.Del("quiet")
	u.RawQuery = q.Encode()
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	scheme := u.Scheme
	h := func(plain string) string {
		if scheme == plain {
			return "http://" + u.Host
		}
		return "https://" + u.Host
	}
	switch scheme {
	case "http", "https":
		if u.Host == "" {
			return r, errors.New("no host")
		}
		r.Channel = &webhookChannel{url: u.String(), client: client, name: scheme + "://" + u.Host}
	case "ntfy", "ntfy+http":
		topic := strings.Trim(u.Path, "/")
		if u.Host == "" || topic == "" || strings.Contains(topic, "/") {
			return r, errors.New("ntfy needs a host and one topic")
		}
		r.Channel = &ntfyChannel{base: h("ntfy+http"), topic: topic, token: q.Get("token"), client: client}
	case "gotify", "gotify+http":
		if u.Host == "" || q.Get("token") == "" {
			return r, errors.New("gotify needs a host and token=")
		}
		r.Channel = &gotifyChannel{base: h("gotify+http") + strings.TrimRight(u.Path, "/"), token: q.Get("token"), client: client}
	case "telegram":
		tok, ok := "", false
		if u.User != nil {
			tok = u.User.Username()
			if p, has := u.User.Password(); has {
				tok, ok = tok+":"+p, true
			}
		}
		if !ok || u.Host == "" {
			return r, errors.New("telegram wants telegram://BOT:TOKEN@CHAT_ID")
		}
		r.Channel = &telegramChannel{base: "https://api.telegram.org", token: tok, chat: u.Host, client: client}
	case "smtp", "smtps":
		c := &smtpChannel{addr: u.Host, implicitTLS: scheme == "smtps"}
		if u.Hostname() == "" {
			return r, errors.New("smtp needs a host")
		}
		if u.Port() == "" {
			port := "587"
			if c.implicitTLS {
				port = "465"
			}
			c.addr = net.JoinHostPort(u.Hostname(), port)
		}
		from, err := mail.ParseAddress(q.Get("from"))
		if err != nil {
			return r, errors.New("smtp needs from=address")
		}
		c.from = from.Address
		for _, t := range strings.Split(q.Get("to"), ",") {
			to, err := mail.ParseAddress(strings.TrimSpace(t))
			if err != nil {
				return r, errors.New("smtp needs to=address[,address]")
			}
			c.to = append(c.to, to.Address)
		}
		if u.User != nil {
			c.user = u.User.Username()
			c.pass, _ = u.User.Password()
		}
		r.Channel = c
	default:
		return r, fmt.Errorf("unknown channel %q", scheme)
	}
	return r, nil
}

// wants says whether this route takes a notice about an anomaly, if it is one.
func (r *Route) wants(a *model.Anomaly) bool {
	if a == nil {
		return true
	}
	if r.Min != "" && model.SeverityRank(a.Severity) < model.SeverityRank(r.Min) {
		return false
	}
	return len(r.Kinds) == 0 || slices.Contains(r.Kinds, a.Kind)
}

func title(p Payload) string {
	switch p.Event {
	case "new_device":
		return "New device"
	case "anomaly":
		if p.Anomaly != nil {
			return "netgraph: " + strings.ReplaceAll(p.Anomaly.Kind, "_", " ")
		}
	case "report":
		return "netgraph report"
	}
	return "netgraph"
}

// urgency is 0 to 2: low, normal, high.
func urgency(p Payload) int {
	if p.Anomaly != nil {
		switch p.Anomaly.Severity {
		case model.SeverityHigh:
			return 2
		case model.SeverityLow:
			return 0
		}
	}
	return 1
}

// postJSON posts and sorts the answer into retryable and permanent. An http client's
// error quotes the URL, which can hold a token, so only its cause is kept.
func postJSON(ctx context.Context, client *http.Client, to string, headers map[string]string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, to, bytes.NewReader(b))
	if err != nil {
		return errors.New("bad channel address")
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return ue.Err
		}
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		return nil
	}
	if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode/100 == 5 {
		return fmt.Errorf("%s", resp.Status)
	}
	return fmt.Errorf("%s: %w", resp.Status, errPermanent)
}

type webhookChannel struct {
	url, name string
	client    *http.Client
}

func (c *webhookChannel) Name() string { return c.name }
func (c *webhookChannel) Send(ctx context.Context, p Payload) error {
	return postJSON(ctx, c.client, c.url, nil, p)
}

type ntfyChannel struct {
	base, topic, token string
	client             *http.Client
}

func (c *ntfyChannel) Name() string { return "ntfy " + c.base + "/" + c.topic }
func (c *ntfyChannel) Send(ctx context.Context, p Payload) error {
	headers := map[string]string{}
	if c.token != "" {
		headers["Authorization"] = "Bearer " + c.token
	}
	return postJSON(ctx, c.client, c.base, headers, map[string]any{
		"topic": c.topic, "title": title(p), "message": p.Text, "priority": []int{2, 3, 4}[urgency(p)],
	})
}

type gotifyChannel struct {
	base, token string
	client      *http.Client
}

func (c *gotifyChannel) Name() string { return "gotify " + c.base }
func (c *gotifyChannel) Send(ctx context.Context, p Payload) error {
	return postJSON(ctx, c.client, c.base+"/message", map[string]string{"X-Gotify-Key": c.token}, map[string]any{
		"title": title(p), "message": p.Text, "priority": []int{2, 5, 8}[urgency(p)],
	})
}

type telegramChannel struct {
	base, token, chat string
	client            *http.Client
}

func (c *telegramChannel) Name() string { return "telegram chat " + c.chat }
func (c *telegramChannel) Send(ctx context.Context, p Payload) error {
	// No parse_mode: names off the network stay plain text.
	return postJSON(ctx, c.client, c.base+"/bot"+c.token+"/sendMessage", nil, map[string]any{
		"chat_id": c.chat, "text": title(p) + "\n" + p.Text, "disable_web_page_preview": true,
	})
}

type smtpChannel struct {
	addr, from, user, pass string
	to                     []string
	implicitTLS            bool
	tlsConfig              *tls.Config // tests
	timeout                time.Duration
}

func (c *smtpChannel) Name() string { return "email via " + c.addr }

// headerSafe keeps a header on its one line, whatever a name off the network holds.
func headerSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

func (c *smtpChannel) message(p Payload) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n",
		c.from, strings.Join(c.to, ", "), mime.QEncoding.Encode("utf-8", headerSafe(title(p))), time.Now().Format(time.RFC1123Z))
	// Bare newlines aren't legal in SMTP, and a line of "." ends the message; the
	// smtp package's writer dot-stuffs, and this normalises the line ends.
	text := strings.ReplaceAll(strings.ReplaceAll(p.Text, "\r\n", "\n"), "\r", "\n")
	b.WriteString(strings.ReplaceAll(text, "\n", "\r\n"))
	b.WriteString("\r\n")
	return b.Bytes()
}

func (c *smtpChannel) Send(ctx context.Context, p Payload) error {
	timeout := c.timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	host, _, err := net.SplitHostPort(c.addr)
	if err != nil {
		return errors.New("bad mail server address")
	}
	cfg := c.tlsConfig
	if cfg == nil {
		cfg = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}
	d := net.Dialer{Timeout: timeout}
	var conn net.Conn
	if c.implicitTLS {
		conn, err = (&tls.Dialer{NetDialer: &d, Config: cfg}).DialContext(ctx, "tcp", c.addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", c.addr)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	cl, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer cl.Close()
	secure := c.implicitTLS
	if ok, _ := cl.Extension("STARTTLS"); ok && !secure {
		if err := cl.StartTLS(cfg); err != nil {
			return err
		}
		secure = true
	}
	if c.user != "" {
		if !mayAuthenticate(secure, host) {
			return fmt.Errorf("the mail server offers no TLS, so the password won't be sent: %w", errPermanent)
		}
		if err := cl.Auth(smtp.PlainAuth("", c.user, c.pass, host)); err != nil {
			return fmt.Errorf("%w: %w", err, errPermanent)
		}
	}
	if err := cl.Mail(c.from); err != nil {
		return err
	}
	for _, to := range c.to {
		if err := cl.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(c.message(p)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

// mayAuthenticate says whether a password can go to this server: never over the
// network in the clear. PlainAuth refuses too, with the same exception.
func mayAuthenticate(secure bool, host string) bool {
	return secure || host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// Held messages while a route is quiet. Past this they're counted.
const maxHeld = 50

// heldDigest is what piled up over quiet hours, as one message.
func heldDigest(held []Payload, dropped int) Payload {
	var b strings.Builder
	total := len(held) + dropped
	fmt.Fprintf(&b, "%d %s during quiet hours:", total, map[bool]string{true: "alert", false: "alerts"}[total == 1])
	for _, p := range held {
		b.WriteString("\n- ")
		b.WriteString(p.Text)
	}
	if dropped > 0 {
		fmt.Fprintf(&b, "\n- and %s more", strconv.Itoa(dropped))
	}
	return NewReportPayload(b.String())
}
