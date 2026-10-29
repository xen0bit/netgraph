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
	// Try each suffix from the longest, slicing the name rather than
	// splitting it: graphs and anomaly checks ask for thousands of names.
	start := 0 // where the label before the suffix begins
	for {
		dot := strings.IndexByte(name[start:], '.')
		if dot < 0 {
			return name
		}
		suffix := name[start+dot+1:]
		if ps, icann := publicsuffix.PublicSuffix(suffix); icann && ps == suffix {
			return name[start:]
		}
		start += dot + 1
	}
}
