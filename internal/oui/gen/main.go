// Command gen rebuilds internal/oui/oui.tsv.gz from the IEEE registries.
//
//	go run ./internal/oui/gen                 # download from standards-oui.ieee.org
//	go run ./internal/oui/gen -dir ./csvs     # use oui.csv, mam.csv, oui36.csv from a directory
//
// The output holds one "PREFIX<TAB>Organization" line per assignment, sorted,
// where PREFIX is 6, 7 or 9 hex digits (MA-L, MA-M, MA-S).
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var sources = []struct{ file, url string }{
	{"oui.csv", "https://standards-oui.ieee.org/oui/oui.csv"},
	{"mam.csv", "https://standards-oui.ieee.org/oui28/mam.csv"},
	{"oui36.csv", "https://standards-oui.ieee.org/oui36/oui36.csv"},
}

func main() {
	dir := flag.String("dir", "", "read CSVs from this directory instead of downloading")
	out := flag.String("o", "internal/oui/oui.tsv.gz", "output file")
	flag.Parse()

	entries := map[string]string{}
	for _, s := range sources {
		data, err := fetch(*dir, s.file, s.url)
		if err != nil {
			log.Fatal(err)
		}
		r := csv.NewReader(bytes.NewReader(data))
		r.FieldsPerRecord = -1
		rows, err := r.ReadAll()
		if err != nil {
			log.Fatalf("%s: %v", s.file, err)
		}
		for _, row := range rows[1:] {
			if len(row) < 3 {
				continue
			}
			prefix := strings.ToUpper(strings.TrimSpace(row[1]))
			name := strings.Join(strings.Fields(row[2]), " ")
			if prefix == "" || name == "" {
				continue
			}
			entries[prefix] = name
		}
	}
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	for _, k := range keys {
		fmt.Fprintf(zw, "%s\t%s\n", k, entries[k])
	}
	zw.Close()
	if err := os.WriteFile(*out, buf.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %d assignments to %s (%d bytes)", len(keys), *out, buf.Len())
}

func fetch(dir, file, url string) ([]byte, error) {
	if dir != "" {
		return os.ReadFile(filepath.Join(dir, file))
	}
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	// The IEEE server rejects requests without a browser-like user agent.
	req.Header.Set("User-Agent", "Mozilla/5.0 (netgraph oui generator)")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}
