#!/bin/sh

CERTPATH=${STENO_CERTS:-/etc/stenographer/certs}
URL=${STENO_URL:-https://127.0.0.1:1234/query}
TIMEOUT=${STENO_TIMEOUT:-890}
MAX_PCAP_BYTES=${STENO_MAX_PCAP_BYTES:-2147483648}

if [ $# -lt 1 ]; then
  echo "Usage: $0 <steno-query> [tcpdump-args]"
  exit 1
fi

query=$1
shift

/usr/bin/curl \
    --cert "$CERTPATH/client_cert.pem" \
    --key "$CERTPATH/client_key.pem" \
    --cacert "$CERTPATH/ca_cert.pem" \
    --silent \
    --max-time $TIMEOUT \
    --header "Steno-Limit-Bytes:$MAX_PCAP_BYTES" \
    --show-error \
    -d "$query" \
    "$URL" |
    /usr/sbin/tcpdump -r /dev/stdin -s 0 "$@"