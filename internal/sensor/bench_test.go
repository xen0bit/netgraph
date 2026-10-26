package sensor

import (
	"context"
	"errors"
	"testing"

	"github.com/xen0bit/netgraph/internal/capture"
	"github.com/xen0bit/netgraph/internal/rdns"
	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wire"
)

type nullEmitter struct{}

func (nullEmitter) Emit(wire.Event) {}

type noPTR struct{}

func (noPTR) LookupAddr(context.Context, string) ([]string, error) {
	return nil, errors.New("no PTR")
}

// BenchmarkHandle measures the per-packet cost of the home scenario, with
// and without reverse DNS observation (which runs on every live packet).
func BenchmarkHandle(b *testing.B) {
	tss, frames := testutil.Home(b).Frames()
	for _, tc := range []struct {
		name string
		rdns bool
	}{{"plain", false}, {"rdns", true}} {
		b.Run(tc.name, func(b *testing.B) {
			cfg := Config{}
			if tc.rdns {
				l := rdns.New(rdns.Config{Resolver: noPTR{}})
				defer l.Close()
				cfg.RDNS = l
			}
			p := NewProcessor(cfg, nullEmitter{})
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				j := i % len(frames)
				p.Handle(tss[j], frames[j], capture.LinkEthernet)
			}
		})
	}
}
