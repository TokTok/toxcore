#!/usr/bin/env bash

set -e

read -r -d '' JQ_SCRIPT << 'EOS' || true
def conf_tpl($addr):
  "  { //\(.maintainer)\n    public_key = \"\(.public_key)\"\n    port = \(.port)\n    address = \"\($addr)\"\n  },";

.nodes[] |
  if .ipv4 != "-" then conf_tpl(.ipv4) else empty end,
  if .ipv6 != "-" then conf_tpl(.ipv6) else empty end
EOS

NODES=$(curl -sf https://nodes.tox.chat/json | jq -r "${JQ_SCRIPT}" | sed -Ee '1h;1!H;$!d;g;s/(.*),/\1/')

if [ x"${NODES}" == x ]; then
    echo 'Failed to get nodes' >&2
    exit 1;
fi

echo -e 'bootstrap_nodes = (\n'"${NODES}"'\n)'
