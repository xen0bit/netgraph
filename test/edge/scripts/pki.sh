#!/bin/sh
# A throwaway certificate for the edge's TLS listeners (AnyConnect), shared
# with the clients on a volume so they can pin it.
set -eu
[ -s /pki/server.crt ] && exit 0
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj /CN=vpn.example.com -addext "subjectAltName=IP:198.18.1.10,DNS:vpn.example.com" \
  -keyout /pki/server.key -out /pki/server.crt
chmod 0644 /pki/server.key /pki/server.crt
