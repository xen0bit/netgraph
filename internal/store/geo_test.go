package store

import (
	"strings"
	"testing"

	"github.com/xen0bit/netgraph/internal/geo"
	"github.com/xen0bit/netgraph/internal/model"
)

func TestSetGeo(t *testing.T) {
	db, err := geo.Parse(strings.NewReader("cidr,continent,country,region,city,org\n203.0.113.0/24,NA,US,California,Los Angeles,Example CDN\n"))
	if err != nil {
		t.Fatal(err)
	}
	st := &Store{cfg: Config{Geo: func() *geo.DB { return db }}}
	flows := []model.Flow{{RemoteIP: "203.0.113.9"}, {RemoteIP: "198.51.100.1"}}
	st.setGeo(flows)
	if flows[0].City != "Los Angeles" || flows[0].Country != "" || flows[0].GeoOrg != "Example CDN" {
		t.Fatalf("geo = %+v", flows[0])
	}
	if flows[1].City != "" {
		t.Fatalf("unknown address got geo: %+v", flows[1])
	}
}
