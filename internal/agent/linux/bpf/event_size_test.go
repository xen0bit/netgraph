//go:build linux

package bpf

import "testing"

// TestEventSize pins the ring buffer record to struct event in src/conn.c.
// The kernel writes eventSize bytes per record and Parse reads fields at fixed
// offsets, so a field, a type or padding changing in C without this constant
// (and the decoder) would silently misread every event. src/conn.c asserts the
// same 88 bytes with _Static_assert; make bpf and CI's bpf job rebuild the
// checked-in objects, so a change there is caught before it drifts.
func TestEventSize(t *testing.T) {
	if eventSize != 88 {
		t.Fatalf("eventSize = %d, want 88: match struct event in src/conn.c and update Parse", eventSize)
	}
}
