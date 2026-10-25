package oui

import "testing"

func TestLookup(t *testing.T) {
	for mac, want := range map[string]string{
		"3c:22:fb:01:02:03": "Apple, Inc.",
		"00:1b:a9:44:55:66": "Brother industries, LTD.",
		"02:00:5e:00:00:01": Randomized,
		"not-a-mac":         "",
	} {
		if got := Lookup(mac); got != want {
			t.Errorf("Lookup(%s) = %q, want %q", mac, got, want)
		}
	}
}

func TestShort(t *testing.T) {
	for in, want := range map[string]string{
		"Apple, Inc.":                 "Apple",
		"Brother industries, LTD.":    "Brother",
		"Samsung Electronics Co.,Ltd": "Samsung",
		"Google, Inc.":                "Google",
		"Raspberry Pi Trading Ltd":    "Raspberry Pi Trading",
		"Intel Corporate":             "Intel",
		"Inc":                         "Inc",
	} {
		if got := Short(in); got != want {
			t.Errorf("Short(%q) = %q, want %q", in, got, want)
		}
	}
}
