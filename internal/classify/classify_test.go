package classify

import (
	"slices"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		name string
		in   Input
		want string
		conf string
	}{
		{"nothing", Input{}, Unknown, ""},
		{"a router says so itself", Input{Role: "router", Vendor: "Apple, Inc."}, Router, High},
		{"a switch, from LLDP", Input{Role: "switch", Vendor: "Intel Corp", Hostnames: []string{"core-switch"}}, Switch, High},
		{"an AP", Input{Role: "access_point", Vendor: "Ubiquiti Inc"}, AP, High},
		{"a printer by protocol", Input{Vendor: "Brother Industries", Hostnames: []string{"BRN001BA9"}, Services: []string{"office printer._ipp._tcp.local"}, Models: []string{"Brother HL-L2350DW"}}, Printer, High},
		{"an iPhone", Input{Vendor: "Apple, Inc.", Hostnames: []string{"alice-iphone"}, Fingerprints: []string{"apple-ios"}}, Phone, High},
		{"an Apple vendor alone only leans", Input{Vendor: "Apple, Inc."}, Phone, Low},
		{"a Windows PC", Input{Vendor: "Micro-Star", Hostnames: []string{"DESKTOP-ABC123"}, Fingerprints: []string{"MSFT 5.0"}}, Computer, High},
		{"a Chromecast", Input{Vendor: "Google, Inc.", Hostnames: []string{"Chromecast-Ultra"}, Services: []string{"living room._googlecast._tcp.local"}}, TV, High},
		{"an IP camera", Input{Vendor: "Hangzhou Hikvision Digital", Serves: []string{"554/tcp"}}, Camera, High},
		{"a smart plug", Input{Vendor: "Espressif Inc.", Hostnames: []string{"shelly1-A1B2"}}, IoT, High},
		{"a NAS", Input{Vendor: "Synology Incorporated", Services: []string{"ds._smb._tcp.local", "ds._adisk._tcp.local"}}, NAS, High},
		{"a console", Input{Vendor: "Sony Interactive Entertainment", Hostnames: []string{"PS5-123"}}, Game, High},
		{"an even conflict is low, and settled by the fixed order", Input{Hostnames: []string{"printer"}, UserAgents: []string{"Windows NT 10.0"}}, Computer, Low},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := Classify(c.in)
			if v.Type != c.want || v.Confidence != c.conf {
				t.Errorf("got %q %q, want %q %q: %+v", v.Type, v.Confidence, c.want, c.conf, v.Reasons)
			}
			if c.want != "" && len(v.Reasons) == 0 {
				t.Error("a verdict with no reasons")
			}
		})
	}
}

// Repeating a claim does not make it truer.
func TestRepetitionDoesNotOutvote(t *testing.T) {
	many := make([]string, 60)
	for i := range many {
		many[i] = "iphone"
	}
	if v := Classify(Input{Hostnames: many, Services: []string{"x._ipp._tcp.local"}, Serves: []string{"9100/tcp"}}); v.Type != Printer {
		t.Errorf("got %q: %+v", v.Type, v.Reasons)
	}
}

func TestDeterministic(t *testing.T) {
	in := Input{Vendor: "Apple", Hostnames: []string{"a-iphone", "b-macbook", "c-ipad"}, UserAgents: []string{"iPad", "Macintosh"}, Services: []string{"x._raop._tcp.local", "y._airplay._tcp.local"}}
	first := Classify(in)
	for range 50 {
		v := Classify(in)
		if v.Type != first.Type || v.Confidence != first.Confidence || !slices.Equal(v.Reasons, first.Reasons) {
			t.Fatalf("differs: %+v, %+v", first, v)
		}
	}
}

// Every rule names a type the map can draw and a person can pick.
func TestRulesNameKnownTypes(t *testing.T) {
	for _, table := range [][]rule{vendorRules, hostRules, serviceRules, modelRules, fingerprintRules, agentRules, upnpRules, portRules} {
		for _, r := range table {
			if !Valid(r.typ) || r.weight <= 0 || r.pat != strings.ToLower(r.pat) {
				t.Errorf("bad rule %+v", r)
			}
		}
	}
}

func FuzzClassify(f *testing.F) {
	f.Add("Apple", "router", "iphone", "x._ipp._tcp.local", "HL-", "apple-ios", "Windows NT", "miniupnpd", "631/tcp")
	f.Fuzz(func(t *testing.T, vendor, role, host, svc, model, fp, ua, upnp, port string) {
		v := Classify(Input{Vendor: vendor, Role: role, Hostnames: []string{host, host}, Services: []string{svc}, Models: []string{model}, Fingerprints: []string{fp}, UserAgents: []string{ua}, UPnP: []string{upnp}, Serves: []string{port}})
		if v.Type != "" && !Valid(v.Type) {
			t.Errorf("unknown type %q", v.Type)
		}
		if (v.Type == "") != (len(v.Reasons) == 0) {
			t.Errorf("type %q with %d reasons", v.Type, len(v.Reasons))
		}
		if len(v.Reasons) > maxReason {
			t.Errorf("%d reasons", len(v.Reasons))
		}
		for _, r := range v.Reasons {
			if len(r.Value) > maxLen && r.Signal != "role" {
				t.Errorf("an unbounded value: %d bytes", len(r.Value))
			}
		}
	})
}
