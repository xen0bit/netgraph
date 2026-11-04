package buildinfo

import "testing"

func TestOlder(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"v1.2.3", "v1.2.4", true},
		{"1.2.3", "v1.10.0", true},
		{"v2.0.0", "v1.9.9", false},
		{"v1.2.3", "v1.2.3", false},
		{"0.0.1-next", "0.0.2", true},
		{"dev", "v1.0.0", false},
		{"v1.0.0", "dev", false},
		{"source", "v1.0.0", false},
		{"", "v1.0.0", false},
		{"1.2", "v1.3.0", false},
		{"v1.a.3", "v1.3.0", false},
	} {
		if got := Older(c.a, c.b); got != c.want {
			t.Errorf("Older(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
