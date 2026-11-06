package blocklist

import (
	"strings"
	"testing"
)

func TestParseHostsAndMatcher(t *testing.T) {
	doc := `# Title: test list
0.0.0.0 ads.example
127.0.0.1 tracker.example # inline
::1 v6.example
1.2.3.0/24
10.0.0.1-10.0.0.9
`
	p, err := Parse(strings.NewReader(doc), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if p.Title != "test list" {
		t.Fatalf("title = %q", p.Title)
	}
	m := New(p.Entries)
	if e, ok := m.MatchName("x.ads.example"); !ok || e.Value != "ads.example" {
		t.Fatalf("domain match = %+v %v", e, ok)
	}
	if e, ok := m.MatchName("tracker.example"); !ok || e.Value != "tracker.example" {
		t.Fatalf("exact match = %+v %v", e, ok)
	}
	if _, ok := m.MatchName("notads.example"); ok {
		t.Fatal("false domain match")
	}
	if e, ok := m.MatchIP("1.2.3.9"); !ok || e.Value != "1.2.3.0/24" {
		t.Fatalf("ip match = %+v %v", e, ok)
	}
	if e, ok := m.MatchIP("10.0.0.5"); !ok || e.Value != "10.0.0.1-10.0.0.9" {
		t.Fatalf("range match = %+v %v", e, ok)
	}
	if _, ok := m.MatchIP("10.0.0.10"); ok {
		t.Fatal("range over-matched")
	}
}

func TestParseLSRules(t *testing.T) {
	doc := `{"title":"r","rules":[
	  {"action":"deny","remote":{"type":"domain","values":["*.ads.example"]}},
	  {"action":"allow","remote":{"type":"domain","values":["ok.example"]}},
	  {"action":"deny","denied-remote-hosts":["bad.example"]}
	],"denied-remote-addresses":["203.0.113.0/24"]}`
	p, err := Parse(strings.NewReader(doc), FormatLSRules)
	if err != nil {
		t.Fatal(err)
	}
	m := New(p.Entries)
	if _, ok := m.MatchName("x.ads.example"); !ok {
		t.Fatal("lsrules domain not matched")
	}
	if _, ok := m.MatchName("ok.example"); ok {
		t.Fatal("allow rule became a block")
	}
	if _, ok := m.MatchIP("203.0.113.9"); !ok {
		t.Fatal("lsrules address not matched")
	}
}

func TestParseRejectsEmptyAndBounds(t *testing.T) {
	if _, err := Parse(strings.NewReader("# only comments\n"), FormatHosts); err == nil {
		t.Fatal("empty list accepted")
	}
	if _, err := Parse(strings.NewReader("x\n"), "nope"); err == nil {
		t.Fatal("bad format accepted")
	}
}
