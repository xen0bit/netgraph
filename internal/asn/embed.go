//go:build embed_asn

package asn

import (
	_ "embed"
	"strings"
)

// The table as `make asn.fetch` downloaded it, and the day it did. Release
// builds embed it; see noembed.go for everything else.
var (
	//go:embed ip2asn-combined.tsv.gz
	embedded []byte
	//go:embed ip2asn.date
	embeddedDate string
)

func embeddedTable() ([]byte, string) { return embedded, strings.TrimSpace(embeddedDate) }
