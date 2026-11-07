//go:build windows

package windows

import (
	"testing"

	"github.com/xen0bit/netgraph/internal/agent/agenttest"
)

// The real TCP table and process list (CI's Windows runner).
func TestLiveScan(t *testing.T) { agenttest.Live(t, &Scanner{}) }
