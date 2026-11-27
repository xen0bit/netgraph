package main

import (
	"testing"

	"github.com/xen0bit/netgraph/internal/model"
)

func TestBlocklistDue(t *testing.T) {
	const now = int64(1_700_000_000_000)
	const day = int64(86400)
	cases := []struct {
		name string
		b    model.Blocklist
		want bool
	}{
		{"never fetched", model.Blocklist{}, true},
		{"just fetched", model.Blocklist{LastSuccess: now - 1000, UpdateInterval: day}, false},
		{"interval passed", model.Blocklist{LastSuccess: now - day*1000, UpdateInterval: day}, true},
		{"default interval due", model.Blocklist{LastSuccess: now - day*1000}, true},
		{"default interval not yet", model.Blocklist{LastSuccess: now - day*1000 + 1}, false},
		{"negative interval means default", model.Blocklist{LastSuccess: now - 1000, UpdateInterval: -5}, false},
		{"failed just now, never fetched", model.Blocklist{LastFailure: now - 60_000}, false},
		{"failed an hour ago, never fetched", model.Blocklist{LastFailure: now - 3_600_000}, true},
		{"failed after a stale success", model.Blocklist{LastSuccess: now - 2*day*1000, LastFailure: now - 60_000, UpdateInterval: day}, false},
		{"short interval retries at that interval", model.Blocklist{LastSuccess: now - 600_000, LastFailure: now - 300_000, UpdateInterval: 300}, true},
		{"an old failure before a success doesn't hold it back", model.Blocklist{LastSuccess: now - day*1000, LastFailure: now - day*1000 - 1, UpdateInterval: day}, true},
	}
	for _, tc := range cases {
		if got := blocklistDue(tc.b, now); got != tc.want {
			t.Errorf("%s: due=%v, want %v", tc.name, got, tc.want)
		}
	}
}
