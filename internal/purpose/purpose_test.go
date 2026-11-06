package purpose

import (
	"strings"
	"testing"
)

func TestParseManifest(t *testing.T) {
	doc := `{"application":"Notes","developer":"Example","website":"https://example.com","connections":[
	  {"host":"*.sync.example.com","purpose":"sync","deny_consequences":"notes do not sync"}]}`
	m, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if m.Connections[0].Host != "sync.example.com" {
		t.Fatalf("host = %q", m.Connections[0].Host)
	}
	for name, doc := range map[string]string{
		"no app":      `{"connections":[{"host":"x.example"}]}`,
		"no host":     `{"application":"x","connections":[{"purpose":"p"}]}`,
		"duplicate":   `{"application":"x","connections":[{"host":"a.example"},{"host":"a.example"}]}`,
		"unknown key": `{"application":"x","connections":[],"nonsense":true}`,
	} {
		if _, err := Parse(strings.NewReader(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
