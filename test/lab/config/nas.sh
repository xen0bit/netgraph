#!/bin/sh
# Samba's NetBIOS name server registers LAB-NAS by broadcast.
set -e
cat > /etc/samba/smb.conf <<CONF
[global]
netbios name = LAB-NAS
workgroup = LAB
interfaces = eth0
bind interfaces only = yes
disable netbios = no
CONF
exec nmbd -F --no-process-group --debug-stdout -d 1
