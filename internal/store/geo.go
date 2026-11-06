package store

import (
	"net/netip"

	"github.com/xen0bit/netgraph/internal/geo"
	"github.com/xen0bit/netgraph/internal/model"
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

// setGeo fills each flow's remote location from the local table. It is a
// no-op when no table is loaded, so the feature needs no schema or backfill.
func (s *Store) setGeo(flows []model.Flow) {
	if s.cfg.Geo == nil {
		return
	}
	db := s.cfg.Geo()
	if db == nil {
		return
	}
	for i := range flows {
		a, err := netip.ParseAddr(flows[i].RemoteIP)
		if err != nil {
			continue
		}
		if info, ok := db.Lookup(a); ok {
			flows[i].Continent = info.Continent
			flows[i].Region = info.Region
			flows[i].City = info.City
			flows[i].GeoOrg = info.Org
		}
	}
}
