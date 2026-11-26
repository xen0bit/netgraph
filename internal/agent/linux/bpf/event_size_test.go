//go:build linux

package bpf

import "testing"

// TestEventSize pins the ring buffer record to struct event in src/conn.c.
// The kernel writes eventSize bytes per record and Parse reads fields at fixed
// offsets, so a field, a type or padding changing in C without this constant
// (and the decoder) would silently misread every event. src/conn.c asserts the
// same 88 bytes with _Static_assert, and TestBPFSourceHash makes sure a source
// change is followed by make bpf.
func TestEventSize(t *testing.T) {
	if eventSize != 88 {
		t.Fatalf("eventSize = %d, want 88: match struct event in src/conn.c and update Parse", eventSize)
	}
}
