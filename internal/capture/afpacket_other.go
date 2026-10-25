//go:build !linux

package capture

import "errors"

// LiveConfig configures live capture.
type LiveConfig struct {
	Interface   string
	RingBytes   int
	Promiscuous bool
}

// OpenLive is only implemented on Linux; elsewhere the sensor can still
// replay pcap files.
func OpenLive(LiveConfig) (Source, error) {
	return nil, errors.New("live capture is only supported on Linux; use -pcap")
}
