//go:build !linux

package conntrack

import "errors"

// Dump is only possible on Linux.
func Dump() ([]Entry, bool, error) {
	return nil, false, errors.New("conntrack: only on Linux")
}
