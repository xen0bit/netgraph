package model

import (
	"strconv"
	"strings"
	"unicode"
)

// CSVText neutralises a spreadsheet formula in text that came from the
// network. Leading whitespace (including non-breaking space) hides a formula
// from a simple prefix test, so skip it before deciding.
func CSVText(s string) string {
	for _, c := range s {
		if unicode.IsSpace(c) || c == '\ufeff' {
			continue
		}
		switch c {
		case '=', '+', '-', '@':
			if c == '-' {
				if _, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
					return s // a negative number, not a formula
				}
			}
			return "'" + s
		}
		return s
	}
	return s
}
