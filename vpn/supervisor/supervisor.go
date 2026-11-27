// Package supervisor is the public name of internal/supervisor: several VPN
// listeners in one process, reconciled to a directory of JSON files, with
// their host networking. netgraph-edge runs its listeners through it.
//
// Everything here is an alias, so these are the engine's own types and not
// copies: a method added there is available here without a line changing.
// The one function that is not an alias is NewManager, which takes a
// standard-library logger where the engine takes its internal wrapper.
package supervisor

import (
	"log/slog"

	isup "github.com/xen0bit/netgraph/vpn/internal/supervisor"
	"github.com/xen0bit/netgraph/vpn/internal/vlog"
)

type (
	// Manager runs and reconciles listeners. See internal/supervisor.
	Manager = isup.Manager
	// ListenerConfig is one listener, as one JSON file holds it.
	ListenerConfig = isup.ListenerConfig
	// Status is a listener's visible state.
	Status = isup.Status
	// Constructor builds a server from a protocol and its options.
	Constructor = isup.Constructor
)

// NewManager returns a Manager for the listener files in dir. A nil ctor means
// client.NewServer, and a nil logger discards.
func NewManager(dir string, logger *slog.Logger, ctor Constructor) *Manager {
	var l *vlog.Logger
	if logger != nil {
		l = vlog.New(logger)
	}
	return isup.NewManager(dir, l, ctor)
}

// LoadDir reads every listener file in dir.
func LoadDir(dir string) (map[string]ListenerConfig, error) { return isup.LoadDir(dir) }

// ValidName reports whether name may name a listener (and its file).
func ValidName(name string) bool { return isup.ValidName(name) }

// KnownProtocol reports whether a server protocol is registered.
func KnownProtocol(protocol string) bool { return isup.KnownProtocol(protocol) }
