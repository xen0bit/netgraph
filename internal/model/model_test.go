package model

import (
	"net/url"
	"testing"
	"time"
)

func TestFilterNetworkRoundTrip(t *testing.T) {
	now := time.Now()
	f, err := ParseFilter(url.Values{"asn": {"AS13335"}, "cc": {"us"}}, now)
	if err != nil || f.ASN != 13335 || f.Country != "US" {
		t.Fatalf("ParseFilter = %+v, %v", f, err)
	}
	back, err := ParseFilter(f.Values(), now)
	if err != nil || back.ASN != f.ASN || back.Country != f.Country {
		t.Errorf("round trip = %+v, %v", back, err)
	}
	for _, bad := range []url.Values{{"asn": {"0"}}, {"asn": {"ASx"}}, {"asn": {"4294967296"}}, {"cc": {"USA"}}, {"cc": {"1A"}}} {
		if _, err := ParseFilter(bad, now); err == nil {
			t.Errorf("ParseFilter(%v) accepted it", bad)
		}
	}
}

func TestFlowNetwork(t *testing.T) {
	for _, c := range []struct {
		f    Flow
		want string
	}{
		{Flow{}, ""},
		{Flow{ASN: 13335}, "AS13335"},
		{Flow{ASN: 13335, ASOrg: "CLOUDFLARENET", Country: "US"}, "AS13335 CLOUDFLARENET · US"},
	} {
		if got := c.f.Network(); got != c.want {
			t.Errorf("Network(%+v) = %q, want %q", c.f, got, c.want)
		}
	}
}
