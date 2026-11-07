//go:build linux

package linux

import (
	"testing"

	"github.com/xen0bit/netgraph/internal/agent/agenttest"
)

func TestLiveScan(t *testing.T) { agenttest.Live(t, &Scanner{}) }
