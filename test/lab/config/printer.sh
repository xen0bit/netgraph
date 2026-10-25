#!/bin/sh
# avahi without D-Bus, announcing an IPP printer.
set -e
mkdir -p /etc/avahi/services /run/avahi-daemon
cat > /etc/avahi/avahi-daemon.conf <<CONF
[server]
host-name=lab-printer
domain-name=local
use-ipv4=yes
use-ipv6=yes
allow-interfaces=eth0
enable-dbus=no
[publish]
publish-addresses=yes
publish-workstation=no
CONF
cat > /etc/avahi/services/ipp.service <<CONF
<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name>Lab Printer</name>
  <service>
    <type>_ipp._tcp</type>
    <port>631</port>
    <txt-record>ty=Brother HL-L2350DW</txt-record>
    <txt-record>pdl=application/pdf</txt-record>
  </service>
</service-group>
CONF
exec avahi-daemon --no-drop-root --no-rlimits
