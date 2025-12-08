#!/bin/bash

if [ "$#" -lt 3 ]; then
        echo "Invalid argument count: needs at least 3 (<ip:port> in, <ip:port> out, <cert_dir>)" >&2
        exit 2
fi

echo -e "Starting KRITIS3M TLS-TCP Reverse Proxy from $1 to $2 with certs in $3\r"
kritis3m_tls proxy \
        --incoming tls://"$1" \
        --outgoing tcp://"$2" \
        --root "$3"/root.pem \
        --cert "$3"/chain.pem \
        --key "$3"/privateKey.pem \
        "${@:4}"
