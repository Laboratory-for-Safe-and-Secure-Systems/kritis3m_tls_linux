#!/bin/bash

if [ "$#" -lt 3 ]; then
        echo "Invalid argument count: needs at least 3 (<ip:port> in, <ip:port> out, <cert_dir>)" >&2
        exit 2
fi


echo -e "Starting KRITIS3M TLS Forward Proxy from $1 to $2 with certs in $3\r"
kritis3m_tls forward_proxy \
        --incoming $1 \
        --outgoing $2 \
        --root $3/root/cert.pem \
        --cert $3/server/chain.pem \
        --key $3/server/privateKey.pem \
        ${@:4}
