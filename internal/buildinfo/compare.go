package buildinfo

import (
	"strconv"
	"strings"
)

// Older says version a is an earlier release than b. Anything that isn't a release number,
// such as "dev" or "source", is never older: there's nothing to say about it.
func Older(a, b string) bool {
	x, ok1 := release(a)
	y, ok2 := release(b)
	if !ok1 || !ok2 {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return false
}

// release reads "v1.2.3" or "1.2.3-next". What's after a dash doesn't count.
func release(v string) ([3]int, bool) {
	var out [3]int
	v, _, _ = strings.Cut(strings.TrimPrefix(v, "v"), "-")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
