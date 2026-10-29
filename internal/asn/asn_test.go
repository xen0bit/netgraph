package asn

import (
	"bytes"
	"compress/gzip"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sample is the format of iptoasn.com's ip2asn-combined.tsv, out of order
// as a hand-edited file might be.
const sample = "1.0.4.0\t1.0.7.255\t38803\tAU\tGTELECOM-AS-AP Gtelecom Pty Ltd\n" +
	"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
	"1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n" +
	"2606:4700::\t2606:4700:ffff:ffff:ffff:ffff:ffff:ffff\t13335\tUS\tCLOUDFLARENET\n" +
	"5.9.0.0\t5.9.255.255\t24940\tDE\tHETZNER-AS\n" +
	"192.0.2.0\t192.0.2.255\t64496\tNone\tDOCUMENTATION\n"

func TestLookup(t *testing.T) {
	db, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if db.Len() != 5 {
		t.Errorf("Len = %d, want 5 (AS 0 skipped)", db.Len())
	}
	for addr, want := range map[string]Info{
		"1.0.0.1":                {13335, "US", "CLOUDFLARENET"},
		"1.0.0.255":              {13335, "US", "CLOUDFLARENET"},
		"1.0.4.0":                {38803, "AU", "GTELECOM-AS-AP Gtelecom Pty Ltd"},
		"1.0.7.255":              {38803, "AU", "GTELECOM-AS-AP Gtelecom Pty Ltd"},
		"5.9.10.11":              {24940, "DE", "HETZNER-AS"},
		"::ffff:5.9.10.11":       {24940, "DE", "HETZNER-AS"},
		"2606:4700::1111":        {13335, "US", "CLOUDFLARENET"},
		"192.0.2.7":              {64496, "", "DOCUMENTATION"},
		"1.0.2.1":                {}, // not routed
		"1.0.8.0":                {}, // past every range
		"0.0.0.1":                {}, // before every range
		"2606:4701::1":           {},
		"2001:db8::1":            {},
		"255.255.255.255":        {},
		"ffff:ffff:ffff:ffff::1": {},
	} {
		got, ok := db.Lookup(netip.MustParseAddr(addr))
		if got != want || ok != (want.ASN != 0) {
			t.Errorf("Lookup(%s) = %+v %v, want %+v", addr, got, ok, want)
		}
	}
	if db.Org(24940) != "HETZNER-AS" || db.Org(1) != "" {
		t.Errorf("Org: %q %q", db.Org(24940), db.Org(1))
	}
	var none *DB
	if _, ok := none.Lookup(netip.MustParseAddr("1.0.0.1")); ok || none.Len() != 0 {
		t.Error("a nil DB knows an address")
	}
}

func TestLoadGzip(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(sample)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ip2asn.tsv.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if info, _ := db.Lookup(netip.MustParseAddr("5.9.0.1")); info.ASN != 24940 {
		t.Errorf("gzipped lookup = %+v", info)
	}
}

func TestParseErrors(t *testing.T) {
	for _, bad := range []string{
		"1.0.0.0\t1.0.0.255\t13335\tUS\n",                            // 4 fields
		"1.0.0.0\t1.0.0.255\t13335\tUS\tX\tY\n",                      // 6 fields
		"1.0.0.9\t1.0.0.1\t13335\tUS\tX\n",                           // backwards
		"1.0.0.0\t2001:db8::\t13335\tUS\tX\n",                        // mixed families
		"1.0.0.0\t1.0.0.255\t99999999999\tUS\tX\n",                   // AS past 32 bits
		"nope\t1.0.0.255\t1\tUS\tX\n",                                // not an address
		strings.Repeat("x", maxLine+1) + "\n",                        // too long
		"1.0.0.0\t1.0.0.255\t13335\tUS\tX\n" + "garbage",             // a bad line after good ones
		"1.0.0.0\t1.0.0.255\t1\tUS\tX\n1.0.0.9\t1.0.1.0\t2\tUS\tY\n", // overlapping
	} {
		if _, err := Parse(strings.NewReader(bad)); err == nil {
			t.Errorf("Parse(%.40q) accepted it", bad)
		}
	}
}

// TestRealFile checks a downloaded table when NETGRAPH_ASN_FILE names one.
func TestRealFile(t *testing.T) {
	path := os.Getenv("NETGRAPH_ASN_FILE")
	if path == "" {
		t.Skip("set NETGRAPH_ASN_FILE to an ip2asn-combined.tsv.gz")
	}
	db, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d ranges", db.Len())
	for addr, want := range map[string]uint32{"1.1.1.1": 13335, "8.8.8.8": 15169, "2606:4700:4700::1111": 13335} {
		if info, _ := db.Lookup(netip.MustParseAddr(addr)); info.ASN != want {
			t.Errorf("Lookup(%s) = %+v, want AS%d", addr, info, want)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(sample))
	f.Add([]byte("::\t::\t1\tZZ\t\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		db, err := Parse(bytes.NewReader(b))
		if err != nil {
			return
		}
		for _, r := range db.v4 {
			if info, ok := db.Lookup(netip.AddrFrom4([4]byte{byte(r.lo >> 24), byte(r.lo >> 16), byte(r.lo >> 8), byte(r.lo)})); !ok || info.ASN == 0 {
				t.Fatalf("range start %d not found", r.lo)
			}
			if len(db.Org(r.asn)) > maxOrg {
				t.Fatal("org too long")
			}
		}
		for _, r := range db.v6 {
			if _, ok := db.Lookup(netip.AddrFrom16(r.hi)); !ok {
				t.Fatalf("range end %x not found", r.hi)
			}
		}
	})
}
