#!/usr/bin/env bash
set -eo pipefail

if [ ! -s /etc/tox-bootstrapd.conf ]; then
    {
        echo "port = ${TOX_PORT:-33445}"
        echo "keys_file_path = \"${TOX_KEYS_FILE_PATH:-/var/lib/tox-bootstrapd/keys}\""
        echo "pid_file_path = \"${TOX_PID_FILE_PATH:-/var/run/tox-bootstrapd/tox-bootstrapd.pid}\""
        echo "enable_ipv6 = ${TOX_ENABLE_IPV6:-false}"
        echo "enable_ipv4_fallback = ${TOX_ENABLE_IPV4_FALLBACK:-true}"
        echo "enable_lan_discovery = ${TOX_ENABLE_LAN_DISCOVERY:-false}"
        echo "enable_tcp_relay = ${TOX_ENABLE_TCP_RELAY:-true}"
        echo "tcp_relay_ports = [${TOX_TCP_RELAY_PORTS:-443,3389,33445}]"
        echo "enable_motd = ${TOX_ENABLE_MOTD:-true}"
        echo "motd = \"${TOX_MOTD:-tox-bootstrapd}\""
        echo ""
    } > /etc/tox-bootstrapd.conf
fi

if [[ "$TOX_UPDATE_NODES" != "no" ]]; then
    sed -e '/^bootstrap_nodes = /,$d' /etc/tox-bootstrapd.conf > /tmp/tbd.conf \
        && cat /tmp/tbd.conf > /etc/tox-bootstrapd.conf \
        && rm /tmp/tbd.conf
    get-nodes.sh >> /etc/tox-bootstrapd.conf
fi

# if command starts with an option, prepend tox-bootstrapd
if [ "${1#-}" != "$1" ]; then
    set -- /usr/local/bin/tox-bootstrapd "$@"
fi

exec "$@"
