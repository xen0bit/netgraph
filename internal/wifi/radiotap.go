package wifi

import (
	"encoding/binary"
	"fmt"
)

// Radio is the part of a radiotap header netgraph uses.
type Radio struct {
	Frequency int // MHz, 0 if absent
	Channel   int // 802.11 channel number, 0 if unknown
	SignalDBM int // dBm, valid when HasSignal
	HasSignal bool
	FCS       bool // a 4-byte frame check sequence follows the frame
	BadFCS    bool // the capture marked the FCS as bad
	DataPad   bool // the 802.11 header is padded to a 4-byte boundary
}

// ParseRadiotap reads a radiotap header and returns the frame that follows.
// It only parses the fields netgraph needs (through field 5), so a capture
// with newer fields still decodes; the header length is authoritative.
func ParseRadiotap(b []byte) (Radio, []byte, error) {
	var r Radio
	if len(b) < 8 || b[0] != 0 {
		return r, nil, fmt.Errorf("radiotap: short or unsupported header")
	}
	hlen := int(binary.LittleEndian.Uint16(b[2:]))
	if hlen < 8 || hlen > len(b) {
		return r, nil, fmt.Errorf("radiotap: header length %d", hlen)
	}
	present := binary.LittleEndian.Uint32(b[4:])
	off := 8
	// Extended present bitmaps follow the first one.
	for present&(1<<31) != 0 {
		if off+4 > hlen {
			return r, nil, fmt.Errorf("radiotap: truncated present bitmap")
		}
		present = binary.LittleEndian.Uint32(b[off:])
		off += 4
	}
	// The fields we use are in the first present word; parse them in order.
	first := binary.LittleEndian.Uint32(b[4:])
	align := func(n int) bool {
		off = (off + n - 1) &^ (n - 1)
		return off <= hlen
	}
	if first&(1<<0) != 0 { // TSFT
		if !align(8) || off+8 > hlen {
			return r, nil, fmt.Errorf("radiotap: truncated TSFT")
		}
		off += 8
	}
	if first&(1<<1) != 0 { // flags
		if off+1 > hlen {
			return r, nil, fmt.Errorf("radiotap: truncated flags")
		}
		flags := b[off]
		r.FCS, r.BadFCS, r.DataPad = flags&0x10 != 0, flags&0x40 != 0, flags&0x20 != 0
		off++
	}
	if first&(1<<2) != 0 { // rate
		if off+1 > hlen {
			return r, nil, fmt.Errorf("radiotap: truncated rate")
		}
		off++
	}
	if first&(1<<3) != 0 { // channel
		if !align(2) || off+4 > hlen {
			return r, nil, fmt.Errorf("radiotap: truncated channel")
		}
		freq := int(binary.LittleEndian.Uint16(b[off:]))
		r.Frequency = freq
		r.Channel = channelForFreq(freq)
		off += 4
	}
	if first&(1<<4) != 0 { // FHSS
		if !align(2) || off+2 > hlen {
			return r, nil, fmt.Errorf("radiotap: truncated FHSS")
		}
		off += 2
	}
	if first&(1<<5) != 0 { // antenna signal
		if off+1 > hlen {
			return r, nil, fmt.Errorf("radiotap: truncated signal")
		}
		r.SignalDBM, r.HasSignal = int(int8(b[off])), true
		off++
	}
	return r, b[hlen:], nil
}

// channelForFreq maps a centre frequency to its 802.11 channel number.
func channelForFreq(freq int) int {
	switch {
	case freq == 2484:
		return 14
	case freq >= 2412 && freq <= 2472:
		return (freq - 2407) / 5
	case freq >= 4910 && freq <= 4980:
		return (freq - 4000) / 5
	case freq >= 5000 && freq <= 5895:
		return (freq - 5000) / 5
	case freq >= 5950 && freq <= 7125:
		return (freq - 5950) / 5
	}
	return 0
}

// FrequencyForChannel is channelForFreq in reverse, for channel hopping.
func FrequencyForChannel(ch int) int {
	switch {
	case ch == 14:
		return 2484
	case ch >= 1 && ch <= 13:
		return 2407 + ch*5
	case ch >= 32 && ch <= 177:
		// 5 GHz and 6 GHz channels overlap numerically; the 6 GHz plan
		// starts at 1, so use the 5 GHz plan for the values WEXT knows.
		return 5000 + ch*5
	}
	return 0
}
