// Package purpose parses netgraph's Internet-access-policy-like metadata:
// what an application connects to, why, and what breaks if it is denied.
// It is documentation, not enforcement.
package purpose

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Connection is one host an application uses.
type Connection struct {
	Host             string `json:"host"`
	Purpose          string `json:"purpose,omitempty"`
	DenyConsequences string `json:"deny_consequences,omitempty"`
}

// Manifest is one application's purpose metadata.
type Manifest struct {
	Application string       `json:"application"`
	Developer   string       `json:"developer,omitempty"`
	Website     string       `json:"website,omitempty"`
	Source      string       `json:"source,omitempty"`
	Connections []Connection `json:"connections"`
}

const maxConnections = 1000

// Parse reads a manifest strictly.
func Parse(r io.Reader) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate rejects a manifest that cannot be shown usefully.
func (m *Manifest) Validate() error {
	m.Application = strings.TrimSpace(m.Application)
	if m.Application == "" {
		return fmt.Errorf("application is required")
	}
	if len(m.Connections) > maxConnections {
		return fmt.Errorf("too many connections (%d, at most %d)", len(m.Connections), maxConnections)
	}
	seen := map[string]bool{}
	for i := range m.Connections {
		c := &m.Connections[i]
		c.Host = strings.ToLower(strings.TrimSpace(c.Host))
		c.Host = strings.TrimPrefix(c.Host, "*.")
		if c.Host == "" {
			return fmt.Errorf("connection %d has no host", i+1)
		}
		if strings.ContainsAny(c.Host, " /\\") {
			return fmt.Errorf("connection %d host %q is not a host name", i+1, c.Host)
		}
		if seen[c.Host] {
			return fmt.Errorf("duplicate host %q", c.Host)
		}
		seen[c.Host] = true
		if len(c.Purpose) > 1000 || len(c.DenyConsequences) > 1000 {
			return fmt.Errorf("connection %d text is too long", i+1)
		}
	}
	return nil
}
