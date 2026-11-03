//go:build !linux

package wifi

// SetChannel is unavailable outside Linux; capture can still run on a fixed
// channel set by the driver.
func SetChannel(iface string, channel int) error { return ErrHopUnsupported }

func SetFrequency(iface string, mhz int) error { return ErrHopUnsupported }
