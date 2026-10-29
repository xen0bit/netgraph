// Package asn maps IP addresses to the autonomous system that announces
// them, with its organisation and country, from an iptoasn.com
// ip2asn-combined file (tab-separated: range start, range end, AS number,
// country, description; plain or gzipped). The server loads it; the sensor
// never does.
package asn

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
)

// Info describes the network an address belongs to.
type Info struct {
	ASN     uint32
	Country string // ISO 3166 alpha-2, or "" when the registry has none
	Org     string
}

// DB is a loaded table. A nil *DB knows no addresses.
type DB struct {
	v4   []range4
	v6   []range6
	orgs map[uint32]string
}

type range4 struct {
	lo, hi uint32
	asn    uint32
	cc     [2]byte
}

type range6 struct {
	lo, hi [16]byte
	asn    uint32
	cc     [2]byte
}

// Bounds on what the file may hold: it is downloaded, so it is not trusted
// to be well formed.
const (
	maxLine   = 1024
	maxOrg    = 128
	maxRanges = 4_000_000
)

// Parse reads a table, gzipped or not. Lines that do not parse are an
// error; ranges of AS 0 (not routed) are skipped.
func Parse(r io.Reader) (*DB, error) {
	br := bufio.NewReader(r)
	if magic, _ := br.Peek(2); bytes.Equal(magic, []byte{0x1f, 0x8b}) {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		br = bufio.NewReader(zr)
	}
	db := &DB{orgs: map[uint32]string{}}
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 0, maxLine), maxLine)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		if text == "" || text[0] == '#' {
			continue
		}
		if err := db.add(text); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if len(db.v4)+len(db.v6) > maxRanges {
			return nil, fmt.Errorf("more than %d ranges", maxRanges)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("line %d: %w", line+1, err)
	}
	// Exact lengths: append left up to a quarter of the table spare.
	db.v4 = append(make([]range4, 0, len(db.v4)), db.v4...)
	db.v6 = append(make([]range6, 0, len(db.v6)), db.v6...)
	slices.SortFunc(db.v4, func(a, b range4) int { return cmpU32(a.lo, b.lo) })
	slices.SortFunc(db.v6, func(a, b range6) int { return bytes.Compare(a.lo[:], b.lo[:]) })
	// Lookup finds the last range starting at or before an address, which
	// is only the right one if ranges do not overlap.
	for i := 1; i < len(db.v4); i++ {
		if db.v4[i].lo <= db.v4[i-1].hi {
			return nil, fmt.Errorf("overlapping ranges at %d", db.v4[i].lo)
		}
	}
	for i := 1; i < len(db.v6); i++ {
		if bytes.Compare(db.v6[i].lo[:], db.v6[i-1].hi[:]) <= 0 {
			return nil, fmt.Errorf("overlapping ranges at %x", db.v6[i].lo)
		}
	}
	return db, nil
}

func cmpU32(a, b uint32) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func (db *DB) add(text string) error {
	f := strings.SplitN(text, "\t", 6)
	if len(f) != 5 {
		return errors.New("want 5 tab-separated fields")
	}
	lo, err := netip.ParseAddr(f[0])
	if err != nil {
		return err
	}
	hi, err := netip.ParseAddr(f[1])
	if err != nil {
		return err
	}
	n, err := strconv.ParseUint(f[2], 10, 32)
	if err != nil {
		return err
	}
	if n == 0 {
		return nil // not routed
	}
	lo, hi = lo.Unmap(), hi.Unmap()
	if lo.Is4() != hi.Is4() || hi.Less(lo) {
		return errors.New("bad range")
	}
	var cc [2]byte
	if c := f[3]; len(c) == 2 && isAlpha(c[0]) && isAlpha(c[1]) {
		cc = [2]byte{upper(c[0]), upper(c[1])}
	}
	asn := uint32(n)
	if _, ok := db.orgs[asn]; !ok {
		org := strings.TrimSpace(f[4])
		if len(org) > maxOrg {
			org = org[:maxOrg]
		}
		db.orgs[asn] = strings.ToValidUTF8(org, "")
	}
	if lo.Is4() {
		db.v4 = append(db.v4, range4{lo: u32(lo), hi: u32(hi), asn: asn, cc: cc})
	} else {
		db.v6 = append(db.v6, range6{lo: lo.As16(), hi: hi.As16(), asn: asn, cc: cc})
	}
	return nil
}

func isAlpha(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }
func upper(c byte) byte   { return c &^ 0x20 }

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// Load reads a table from a file.
func Load(path string) (*DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	db, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return db, nil
}

// Embedded parses the table built into this binary, and returns the day
// it was downloaded. Release builds carry one (the embed_asn build tag,
// with the file `make asn.fetch` downloads); other builds return nil.
func Embedded() (*DB, string, error) {
	b, date := embeddedTable()
	if len(b) == 0 {
		return nil, "", nil
	}
	db, err := Parse(bytes.NewReader(b))
	if err != nil {
		return nil, "", fmt.Errorf("built-in table: %w", err)
	}
	return db, date, nil
}

// Len is the number of routed ranges.
func (db *DB) Len() int {
	if db == nil {
		return 0
	}
	return len(db.v4) + len(db.v6)
}

// Lookup returns the network announcing an address.
func (db *DB) Lookup(a netip.Addr) (Info, bool) {
	if db == nil || !a.IsValid() {
		return Info{}, false
	}
	a = a.Unmap()
	var asn uint32
	var cc [2]byte
	if a.Is4() {
		x := u32(a)
		i, _ := slices.BinarySearchFunc(db.v4, x, func(r range4, x uint32) int {
			if r.lo <= x {
				return -1
			}
			return 1
		})
		if i == 0 || db.v4[i-1].hi < x {
			return Info{}, false
		}
		asn, cc = db.v4[i-1].asn, db.v4[i-1].cc
	} else {
		x := a.As16()
		i, _ := slices.BinarySearchFunc(db.v6, x, func(r range6, x [16]byte) int {
			if bytes.Compare(r.lo[:], x[:]) <= 0 {
				return -1
			}
			return 1
		})
		if i == 0 || bytes.Compare(db.v6[i-1].hi[:], x[:]) < 0 {
			return Info{}, false
		}
		asn, cc = db.v6[i-1].asn, db.v6[i-1].cc
	}
	info := Info{ASN: asn, Org: db.orgs[asn]}
	if cc != [2]byte{} {
		info.Country = string(cc[:])
	}
	return info, true
}

// Org is the organisation name of an AS, "" if the table does not list it.
func (db *DB) Org(asn uint32) string {
	if db == nil {
		return ""
	}
	return db.orgs[asn]
}
