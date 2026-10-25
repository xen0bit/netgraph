// Package oui maps MAC addresses to the organisation the IEEE assigned
// their prefix to. The registry (MA-L, MA-M and MA-S) is embedded; refresh
// it with `make oui.update`.
package oui

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"net"
	"strings"
	"sync"
)

//go:generate go run ./gen -o oui.tsv.gz

//go:embed oui.tsv.gz
var registry []byte

var (
	once  sync.Once
	table map[string]string // hex prefix (6, 7 or 9 digits) -> organisation
)

func load() {
	table = make(map[string]string, 60000)
	zr, err := gzip.NewReader(bytes.NewReader(registry))
	if err != nil {
		return
	}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "\t"); ok {
			table[k] = v
		}
	}
}

// Randomized is the vendor reported for locally administered addresses:
// phones and laptops randomise their MAC per network, and such an address
// belongs to no organisation.
const Randomized = "(randomized)"

// Lookup returns the organisation for a MAC address, the most specific
// assignment first (MA-S, then MA-M, then MA-L). Locally administered
// addresses return Randomized; unknown ones return "".
func Lookup(mac string) string {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) < 6 {
		return ""
	}
	if IsLocal(hw) {
		return Randomized
	}
	once.Do(load)
	h := strings.ToUpper(strings.ReplaceAll(hw.String(), ":", ""))
	for _, n := range []int{9, 7, 6} {
		if v, ok := table[h[:n]]; ok {
			return v
		}
	}
	return ""
}

// IsLocal reports whether a MAC is locally administered (the U/L bit).
func IsLocal(hw net.HardwareAddr) bool { return len(hw) > 0 && hw[0]&0x02 != 0 }

// IsMulticast reports whether a MAC is a group address.
func IsMulticast(hw net.HardwareAddr) bool { return len(hw) > 0 && hw[0]&0x01 != 0 }

// Short trims the corporate suffixes that make vendor names long in a graph
// label: "Apple, Inc." -> "Apple", "Samsung Electronics Co.,Ltd" ->
// "Samsung".
func Short(org string) string {
	s := strings.TrimRight(org, " .,")
	for {
		i := strings.LastIndexAny(s, " ,.")
		if i <= 0 {
			return s
		}
		if !corporate[strings.ToLower(s[i+1:])] {
			return s
		}
		s = strings.TrimRight(s[:i], " .,")
	}
}

var corporate = map[string]bool{
	"inc": true, "incorporated": true, "ltd": true, "limited": true, "co": true, "corp": true,
	"corporation": true, "corporate": true, "llc": true, "gmbh": true, "ag": true, "sa": true, "bv": true,
	"ab": true, "oy": true, "srl": true, "spa": true, "kg": true, "plc": true, "pte": true, "pty": true,
	"technologies": true, "technology": true, "electronics": true, "international": true, "industries": true,
	"": true,
}
