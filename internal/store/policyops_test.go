package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/policy"
)

// A learned policy is only worth anything if the simulator agrees it breaks nothing it saw.
func TestLearnedPolicyBlocksNothingItSaw(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	const mac = "3c:22:fb:01:02:03"
	w := win(0, time.Hour)
	got, err := st.LearnPolicy(ctx, "device:"+mac, w)
	if err != nil {
		t.Fatal(err)
	}
	if got.Connections == 0 || len(got.Policy.Rules) == 0 {
		t.Fatalf("%+v", got)
	}
	if err := got.Policy.Validate(); err != nil {
		t.Fatal(err)
	}
	res, err := st.WhatIf(ctx, got.Policy, w, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range append(res.Blocked, res.Essential...) {
		if imp.Device == "device:"+mac {
			t.Errorf("blocks what it learned from: %+v", imp)
		}
	}
	if res.Summary.Unchanged == 0 {
		t.Errorf("%+v", res.Summary)
	}
	// Tighten it by a rule, and the simulator sees the difference.
	tight := *got.Policy
	tight.Rules = tight.Rules[1:]
	res, err = st.WhatIf(ctx, &tight, w, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary.Blocked == 0 {
		t.Errorf("removing a rule stopped nothing: %+v", res.Summary)
	}
}

func TestLearnWithNothingToLearnFrom(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	if _, err := st.LearnPolicy(ctx, "device:00:00:00:00:00:01", win(0, time.Hour)); err == nil {
		t.Error("learned from nothing")
	}
	if _, err := st.LearnPolicy(ctx, "", win(0, time.Hour)); err == nil {
		t.Error("learned about no device")
	}
}

func TestExportUsesWhatWasSeen(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	const mac = "3c:22:fb:01:02:03"
	w := win(0, time.Hour)
	learned, err := st.LearnPolicy(ctx, "device:"+mac, w)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{policy.FormatNftables, policy.FormatOpenWrt, policy.FormatOPNsense} {
		out, err := st.ExportPolicy(ctx, learned.Policy, format, w)
		if err != nil {
			t.Fatal(err)
		}
		devices, err := st.Devices(ctx, model.Filter{From: w.From, To: w.To, Device: mac})
		if err != nil || len(devices) == 0 {
			t.Fatalf("%+v %v", devices, err)
		}
		if len(devices[0].IPs) == 0 || !strings.Contains(out.Config, devices[0].IPs[0]) {
			t.Errorf("%s: the device's address isn't in:\n%s", format, out.Config)
		}
	}
	if _, err := st.ExportPolicy(context.Background(), learned.Policy, "iptables", w); err == nil {
		t.Error("exported to an unknown format")
	}
}
