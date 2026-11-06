// Package geo maps addresses to a city, region and organisation from a local
// CSV table. It never makes a network request per lookup: the server loads one
// file and replaces it when the operator updates it.
package geo

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// Info is the location of an address. Missing fields are empty.
type Info struct {
	Continent string
	Country   string
	Region    string
	City      string
	Org       string
}

// DB is a loaded geo table. A nil *DB knows nothing.
type DB struct {
	ranges []geoRange
}

type geoRange struct {
	lo, hi netip.Addr
	info   Info
}

// Source describes where the table came from, for the status endpoint.
type Source struct {
	Path string
	AsOf string
}

const maxRanges = 5_000_000

// Parse reads CSV. The header is optional. Accepted columns:
//
//	start,end,continent,country,region,city,org
//	cidr,continent,country,region,city,org
//
// Lines beginning with # are ignored.
func Parse(r io.Reader) (*DB, error) {
	cr := csv.NewReader(bufio.NewReader(r))
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true
	db := &DB{}
	line := 0
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		line++
		if len(rec) == 0 {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(rec[0]), "#") {
			continue
		}
		if line == 1 && !looksLikeAddr(rec[0]) {
			continue // header
		}
		if len(db.ranges) >= maxRanges {
			return nil, fmt.Errorf("geo table is larger than %d ranges", maxRanges)
		}
		g, err := parseRecord(rec)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		db.ranges = append(db.ranges, g)
	}
	if len(db.ranges) == 0 {
		return nil, fmt.Errorf("geo table has no ranges")
	}
	return db, nil
}

func looksLikeAddr(s string) bool {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") || strings.Contains(s, "-") {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

func parseRecord(rec []string) (geoRange, error) {
	if len(rec) < 2 {
		return geoRange{}, fmt.Errorf("not enough columns")
	}
	first := strings.TrimSpace(rec[0])
	var lo, hi netip.Addr
	var rest []string
	if strings.Contains(first, "/") {
		p, err := netip.ParsePrefix(first)
		if err != nil {
			return geoRange{}, err
		}
		lo, hi = p.Masked().Addr().Unmap(), lastAddr(p)
		rest = rec[1:]
	} else {
		if len(rec) < 3 {
			return geoRange{}, fmt.Errorf("not enough columns")
		}
		var err error
		lo, err = netip.ParseAddr(first)
		if err != nil {
			return geoRange{}, err
		}
		hi, err = netip.ParseAddr(strings.TrimSpace(rec[1]))
		if err != nil {
			return geoRange{}, err
		}
		lo, hi = lo.Unmap(), hi.Unmap()
		rest = rec[2:]
	}
	if lo.Is4() != hi.Is4() || lo.Compare(hi) > 0 {
		return geoRange{}, fmt.Errorf("bad range %s-%s", lo, hi)
	}
	info := Info{}
	if len(rest) > 0 {
		info.Continent = strings.TrimSpace(rest[0])
	}
	if len(rest) > 1 {
		info.Country = strings.ToUpper(strings.TrimSpace(rest[1]))
	}
	if len(rest) > 2 {
		info.Region = strings.TrimSpace(rest[2])
	}
	if len(rest) > 3 {
		info.City = strings.TrimSpace(rest[3])
	}
	if len(rest) > 4 {
		info.Org = strings.TrimSpace(rest[4])
	}
	return geoRange{lo: lo, hi: hi, info: info}, nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().Unmap()
	bits := p.Bits()
	if a.Is4() {
		v := a.As4()
		for i := 0; i < 4; i++ {
			host := 32 - bits - (3-i)*8
			if host <= 0 {
				continue
			}
			if host > 8 {
				host = 8
			}
			v[i] |= byte((1 << host) - 1)
		}
		return netip.AddrFrom4(v)
	}
	v := a.As16()
	for i := 0; i < 16; i++ {
		host := 128 - bits - (15-i)*8
		if host <= 0 {
			continue
		}
		if host > 8 {
			host = 8
		}
		v[i] |= byte((1 << host) - 1)
	}
	return netip.AddrFrom16(v)
}

// Lookup finds the first range containing addr.
func (db *DB) Lookup(addr netip.Addr) (Info, bool) {
	if db == nil {
		return Info{}, false
	}
	a := addr.Unmap()
	for _, r := range db.ranges {
		if a.Compare(r.lo) >= 0 && a.Compare(r.hi) <= 0 {
			return r.info, true
		}
	}
	return Info{}, false
}

// Len reports the number of ranges.
func (db *DB) Len() int {
	if db == nil {
		return 0
	}
	return len(db.ranges)
}
