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

func TestLookupNestedAndV6(t *testing.T) {
	doc := `10.0.0.0/8,EU,DE,,Berlin,Wide
10.1.0.0/16,EU,DE,,Hamburg,Narrow
11.0.0.0,11.0.0.9,EU,FR,,Paris,Range
2001:db8::/32,EU,NL,,Amsterdam,Six
`
	db, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	for ip, city := range map[string]string{
		"10.1.2.3": "Hamburg", "10.2.0.1": "Berlin", "10.255.255.255": "Berlin",
		"11.0.0.9": "Paris", "2001:db8:ffff::1": "Amsterdam", "::ffff:10.1.0.1": "Hamburg",
	} {
		info, ok := db.Lookup(netip.MustParseAddr(ip))
		if !ok || info.City != city {
			t.Errorf("%s = %+v %v, want %s", ip, info, ok, city)
		}
	}
	for _, ip := range []string{"11.0.0.10", "9.255.255.255", "2001:db9::1"} {
		if info, ok := db.Lookup(netip.MustParseAddr(ip)); ok {
			t.Errorf("%s matched %+v", ip, info)
		}
	}
}
