//go:build darwin

package darwin

import (
	"testing"

	"github.com/xen0bit/netgraph/internal/agent/agenttest"
)

// The real lsof and ps (CI's macOS runner).
func TestLiveScan(t *testing.T) { agenttest.Live(t, &Scanner{}) }
