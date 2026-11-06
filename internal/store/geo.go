package store

import (
	"net/netip"

	"github.com/xen0bit/netgraph/internal/geo"
)

// GeoLookup returns the local geo table's answer for one address.
func (s *Store) GeoLookup(ip string) (geo.Info, bool) {
	if s.cfg.Geo == nil {
		return geo.Info{}, false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return geo.Info{}, false
	}
	return s.cfg.Geo().Lookup(a)
}

// GeoStatus says whether a geo table is loaded and how many ranges it has.
func (s *Store) GeoStatus() (loaded bool, ranges int) {
	if s.cfg.Geo == nil {
		return false, 0
	}
	db := s.cfg.Geo()
	if db == nil {
		return false, 0
	}
	return true, db.Len()
}
