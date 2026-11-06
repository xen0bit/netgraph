package geo

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseAndLookup(t *testing.T) {
	doc := `start,end,continent,country,region,city,org
1.0.0.0,1.0.0.255,OC,AU,Queensland,Brisbane,Example
203.0.113.0/24,NA,US,California,Los Angeles,Example CDN
`
	db, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if db.Len() != 2 {
		t.Fatalf("ranges = %d", db.Len())
	}
	info, ok := db.Lookup(netip.MustParseAddr("1.0.0.7"))
	if !ok || info.City != "Brisbane" || info.Country != "AU" {
		t.Fatalf("info = %+v %v", info, ok)
	}
	info, ok = db.Lookup(netip.MustParseAddr("203.0.113.9"))
	if !ok || info.Org != "Example CDN" {
		t.Fatalf("cidr info = %+v %v", info, ok)
	}
	if _, ok := db.Lookup(netip.MustParseAddr("198.51.100.1")); ok {
		t.Fatal("unknown address matched")
	}
}
