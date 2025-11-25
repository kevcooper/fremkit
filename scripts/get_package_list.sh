#!/bin/sh

PARENT="$(dirname "$0")"
cd "$PARENT/../lists" || exit 1
curl -sLO "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv"
