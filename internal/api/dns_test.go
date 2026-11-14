package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xen0bit/netgraph/internal/apiclient"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/store"
)

type fakeDNS struct{ reloads atomic.Int32 }

func (f *fakeDNS) Status() *model.DNSServerStatus {
	return &model.DNSServerStatus{Enabled: true, Listen: []string{"udp :53"}, Upstreams: []model.DNSUpstreamStatus{{Name: "https://dns.example", Healthy: true}}}
}
func (f *fakeDNS) Reload() { f.reloads.Add(1) }

// Reading the rules is a viewer's, changing them an operator's; a change
// tells the server to reread them.
func TestDNSRoutes(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "ng.db"), store.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	dns := &fakeDNS{}
	srv := httptest.NewServer(New(Config{Store: st, ReadToken: "r", OperatorToken: "o", DNS: dns}))
	defer srv.Close()
	ctx := context.Background()
	viewer, operator := apiclient.NewClient(srv.URL, "r"), apiclient.NewClient(srv.URL, "o")

	if _, err := viewer.SaveDNSRule(ctx, &model.DNSRule{Action: "block", Pattern: "ads.example"}); err == nil || !strings.Contains(err.Error(), "403") && !strings.Contains(err.Error(), "role") {
		t.Fatalf("a viewer added a rule: %v", err)
	}
	r, err := operator.SaveDNSRule(ctx, &model.DNSRule{Action: "block", Pattern: "ads.example"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operator.SaveDNSRule(ctx, &model.DNSRule{Action: "block", Pattern: "bad name!"}); err == nil || !strings.Contains(err.Error(), "400") && !strings.Contains(err.Error(), "not a name") {
		t.Errorf("a bad pattern: %v", err)
	}
	rules, err := viewer.DNSRules(ctx)
	if err != nil || len(rules) != 1 || rules[0].ID != r.ID {
		t.Fatalf("rules = %+v, %v", rules, err)
	}
	// The one-step form, for a device.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/dns/block", strings.NewReader(`{"name":"ads.example","action":"allow","device":"device:02:00:00:00:00:01"}`))
	req.Header.Set("Authorization", "Bearer o")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var quick model.DNSRule
	_ = json.NewDecoder(resp.Body).Decode(&quick)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || quick.Scope != model.DNSScopeDevice || quick.ScopeValue != "02:00:00:00:00:01" || quick.Action != model.DNSAllow {
		t.Fatalf("quick rule %d %+v", resp.StatusCode, quick)
	}
	if err := operator.DeleteDNSRule(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if dns.reloads.Load() < 3 {
		t.Errorf("the server was told to reload %d times after 3 changes", dns.reloads.Load())
	}
	st2, err := viewer.DNSServer(ctx)
	if err != nil || !st2.Enabled || st2.Upstreams[0].Name != "https://dns.example" {
		t.Errorf("status = %+v, %v", st2, err)
	}
	if _, err := viewer.DNSStats(ctx, window); err != nil {
		t.Errorf("stats: %v", err)
	}
}

func TestDNSServerOff(t *testing.T) {
	srv, _ := serve(t, nil)
	st, err := apiclient.NewClient(srv.URL, "rd-tok").DNSServer(context.Background())
	if err != nil || st.Enabled {
		t.Fatalf("status without a DNS server: %+v, %v", st, err)
	}
}
