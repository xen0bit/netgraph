#!/bin/sh
set -e
ip route replace default via 198.18.0.10
exec labapp web
