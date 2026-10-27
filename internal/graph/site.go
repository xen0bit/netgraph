package graph

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Site is the registrable domain a name belongs to: "time.com" for
// auth.time.com, "bbc.co.uk" for www.bbc.co.uk. It uses the ICANN part of
// the public suffix list only, so a CDN's customer names group under the
// CDN ("cloudfront.net", "fastly.net") rather than each becoming a site of
// its own. A name with no ICANN suffix (printer.local, router.lan) is its
// own site.
func Site(name string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	labels := strings.Split(name, ".")
	for i := 1; i < len(labels); i++ {
		suffix := strings.Join(labels[i:], ".")
		if ps, icann := publicsuffix.PublicSuffix(suffix); icann && ps == suffix {
			return strings.Join(labels[i-1:], ".")
		}
	}
	return name
}
