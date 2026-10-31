package main

import "testing"

func TestCheckRequiresInterface(t *testing.T) {
	if err := check(nil); err == nil {
		t.Fatal("check without -iface succeeded")
	}
}
