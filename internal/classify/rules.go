package classify

import "strings"

// rule points a signal at a type. Patterns are lower-case. A pattern matches
// anywhere in the value unless it starts with "^", when it must lead it (a
// boundary test, not a regular expression: everything here runs over strings
// off the network, so nothing here can backtrack).
//
// Weights: 8 and up nearly settles it on its own (a printer protocol, a console's
// own name); 4 to 7 is good evidence; 1 to 3 only leans, like a vendor that makes
// many kinds of thing.
type rule struct {
	pat    string
	typ    string
	weight int
}

func (r rule) match(low string) bool {
	if p, ok := strings.CutPrefix(r.pat, "^"); ok {
		return strings.HasPrefix(low, p)
	}
	return strings.Contains(low, r.pat)
}

var vendorRules = []rule{
	{"brother", Printer, 5}, {"seiko epson", Printer, 5}, {"epson", Printer, 4}, {"lexmark", Printer, 6}, {"kyocera", Printer, 5}, {"xerox", Printer, 6},
	{"canon", Printer, 3}, {"hewlett packard", Printer, 2}, {"hp inc", Printer, 2},
	{"roku", TV, 7}, {"vizio", TV, 6}, {"tcl", TV, 3}, {"lg electronics", TV, 2}, {"hisense", TV, 5},
	{"sonos", Speaker, 8}, {"bose", Speaker, 6},
	{"synology", NAS, 8}, {"qnap", NAS, 8}, {"western digital", NAS, 3},
	{"hikvision", Camera, 8}, {"dahua", Camera, 8}, {"axis communications", Camera, 8}, {"reolink", Camera, 8}, {"wyze", Camera, 6}, {"arlo", Camera, 7}, {"amcrest", Camera, 8},
	{"nintendo", Game, 8}, {"sony interactive", Game, 8},
	{"espressif", IoT, 6}, {"tuya", IoT, 7}, {"shelly", IoT, 7}, {"allterco", IoT, 7}, {"signify", IoT, 7}, {"philips lighting", IoT, 7}, {"ecobee", IoT, 7}, {"nest labs", IoT, 6}, {"ring llc", Camera, 5}, {"irobot", IoT, 7}, {"tp-link smart", IoT, 5},
	{"ubiquiti", AP, 5}, {"ruckus", AP, 6}, {"aruba", AP, 5}, {"netgear", Router, 2}, {"mikrotik", Router, 5}, {"tp-link", Router, 1}, {"asustek", Router, 1},
	{"raspberry pi", Server, 3}, {"supermicro", Server, 6},
	{"intel corp", Computer, 3}, {"microsoft", Computer, 2}, {"dell", Computer, 3}, {"lenovo", Computer, 3}, {"micro-star", Computer, 3}, {"gigabyte", Computer, 3}, {"apple", Phone, 1}, {"samsung", Phone, 1}, {"oneplus", Phone, 6}, {"xiaomi", Phone, 2},
	{"amazon", IoT, 2},
}

var hostRules = []rule{
	{"iphone", Phone, 9}, {"android", Phone, 6}, {"galaxy", Phone, 5}, {"pixel", Phone, 5}, {"oneplus", Phone, 7},
	{"ipad", Tablet, 9}, {"tablet", Tablet, 6}, {"kindle", Tablet, 6},
	{"macbook", Computer, 9}, {"imac", Computer, 8}, {"mac-mini", Computer, 7}, {"macmini", Computer, 7}, {"^desktop-", Computer, 8}, {"^laptop-", Computer, 8}, {"laptop", Computer, 6}, {"desktop", Computer, 5}, {"thinkpad", Computer, 8}, {"workstation", Computer, 5},
	{"printer", Printer, 7}, {"^brn", Printer, 5}, {"^brw", Printer, 5}, {"laserjet", Printer, 9}, {"officejet", Printer, 9}, {"deskjet", Printer, 9}, {"epson", Printer, 6}, {"canon", Printer, 4},
	{"chromecast", TV, 9}, {"appletv", TV, 9}, {"apple-tv", TV, 9}, {"firetv", TV, 9}, {"fire-tv", TV, 9}, {"roku", TV, 9}, {"webostv", TV, 9}, {"bravia", TV, 8}, {"smarttv", TV, 8}, {"shield", TV, 4},
	{"sonos", Speaker, 9}, {"homepod", Speaker, 9}, {"echo-", Speaker, 6}, {"alexa", Speaker, 6},
	{"synology", NAS, 8}, {"diskstation", NAS, 9}, {"qnap", NAS, 8}, {"truenas", NAS, 9}, {"freenas", NAS, 9}, {"^nas", NAS, 5},
	{"camera", Camera, 7}, {"^cam-", Camera, 6}, {"ring-", Camera, 5}, {"wyze", Camera, 6}, {"doorbell", Camera, 7},
	{"playstation", Game, 9}, {"^ps4", Game, 8}, {"^ps5", Game, 8}, {"xbox", Game, 9}, {"nintendo", Game, 9},
	{"esphome", IoT, 8}, {"^esp-", IoT, 7}, {"^esp32", IoT, 7}, {"^esp8266", IoT, 7}, {"tasmota", IoT, 9}, {"shelly", IoT, 8}, {"philips-hue", IoT, 8}, {"thermostat", IoT, 8}, {"nest-", IoT, 5}, {"roomba", IoT, 8}, {"homeassistant", Server, 6},
	{"unifi", AP, 5}, {"^ap-", AP, 5}, {"openwrt", Router, 7}, {"fritz", Router, 7}, {"router", Router, 7}, {"gateway", Router, 5},
	{"server", Server, 4}, {"proxmox", Server, 8}, {"^pve", Server, 5},
}

var serviceRules = []rule{
	{"._ipp._tcp", Printer, 9}, {"._ipps._tcp", Printer, 9}, {"._printer._tcp", Printer, 9}, {"._pdl-datastream._tcp", Printer, 9}, {"._scanner._tcp", Printer, 5},
	{"._googlecast._tcp", TV, 6}, {"._amzn-wplay._tcp", TV, 7}, {"._androidtvremote", TV, 9}, {"._roku", TV, 9}, {"._airplay._tcp", TV, 3},
	{"._sonos._tcp", Speaker, 9}, {"._spotify-connect._tcp", Speaker, 4}, {"._raop._tcp", Speaker, 3},
	{"._apple-mobdev2._tcp", Phone, 8}, {"._companion-link._tcp", Phone, 2},
	{"._smb._tcp", Computer, 2}, {"._afpovertcp._tcp", NAS, 3}, {"._nfs._tcp", NAS, 4}, {"._adisk._tcp", NAS, 5}, {"._workstation._tcp", Computer, 3}, {"._rfb._tcp", Computer, 3}, {"._ssh._tcp", Server, 2}, {"._sftp-ssh._tcp", Server, 2},
	{"._axis-video._tcp", Camera, 9}, {"._rtsp._tcp", Camera, 4}, {"._nvstream", Game, 3},
	{"._hap._tcp", IoT, 6}, {"._homekit._tcp", IoT, 6}, {"._matter._tcp", IoT, 7}, {"._matterc._udp", IoT, 7}, {"._esphomelib._tcp", IoT, 9}, {"._hue._tcp", IoT, 8}, {"._shelly._tcp", IoT, 9}, {"._home-assistant._tcp", Server, 8},
}

var modelRules = []rule{
	{"appletv", TV, 9}, {"apple tv", TV, 9}, {"chromecast", TV, 9}, {"bravia", TV, 8}, {"shield android", TV, 9},
	{"iphone", Phone, 9}, {"ipad", Tablet, 9}, {"macbook", Computer, 9}, {"imac", Computer, 9}, {"macmini", Computer, 8},
	{"homepod", Speaker, 9}, {"audio", Speaker, 4}, {"sonos", Speaker, 9},
	{"hl-", Printer, 6}, {"laserjet", Printer, 9}, {"officejet", Printer, 9}, {"deskjet", Printer, 9}, {"pixma", Printer, 9}, {"workforce", Printer, 7},
	{"diskstation", NAS, 9}, {"synology", NAS, 8}, {"qnap", NAS, 8},
}

var fingerprintRules = []rule{
	{"apple-ios", Phone, 6}, {"android-dhcp", Phone, 7}, {"msft", Computer, 6}, {"apple-mac", Computer, 6}, {"udhcp", IoT, 3}, {"espressif", IoT, 6}, {"dhcpcd", Server, 1},
}

var agentRules = []rule{
	{"iphone", Phone, 8}, {"ipad", Tablet, 8}, {"android", Phone, 5}, {"windows nt", Computer, 7}, {"macintosh", Computer, 6}, {"x11; linux", Computer, 4}, {"cros ", Computer, 7},
	{"crkey", TV, 9}, {"roku", TV, 9}, {"smarttv", TV, 8}, {"smart-tv", TV, 8}, {"tizen", TV, 6}, {"webos", TV, 6},
	{"playstation", Game, 9}, {"xbox", Game, 9}, {"nintendo", Game, 9},
	{"sonos", Speaker, 9},
}

var upnpRules = []rule{
	{"internetgatewaydevice", Router, 8}, {"mediarenderer", TV, 4}, {"mediaserver", NAS, 2}, {"synology", NAS, 7}, {"roku", TV, 8}, {"sonos", Speaker, 8},
	{"xbox", Game, 8}, {"playstation", Game, 8}, {"windows", Computer, 2}, {"openwrt", Router, 6}, {"miniupnpd", Router, 5}, {"hikvision", Camera, 8},
}

var portRules = []rule{
	{"^631/tcp", Printer, 4}, {"^9100/tcp", Printer, 7}, {"^515/tcp", Printer, 5},
	{"^554/tcp", Camera, 4}, {"^8009/tcp", TV, 4}, {"^445/tcp", NAS, 2}, {"^2049/tcp", NAS, 4}, {"^5000/tcp", NAS, 1}, {"^22/tcp", Server, 1}, {"^3389/tcp", Computer, 4}, {"^1400/tcp", Speaker, 6}, {"^8123/tcp", Server, 5},
}
