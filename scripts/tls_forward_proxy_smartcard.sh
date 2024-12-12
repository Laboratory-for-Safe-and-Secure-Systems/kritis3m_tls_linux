#!/bin/bash

if [ "$#" -lt 5 ]; then
        echo "Invalid argument count: needs at least 5 (<ip:port> in, <ip:port> out, <cert_dir>, <label> of PKCS#11 private key, <path> PKCS#11 middleware)" >&2
        exit 2
fi

echo -e "Starting KRITIS3M TLS Forward Proxy from $1 to $2 with certs in $3\r"
kritis3m_tls forward_proxy \
        --incoming "$1" \
        --outgoing "$2" \
        --root "$3"/root.pem \
        --cert "$3"/chain.pem \
        --key pkcs11:"$4" \
        --pkcs11_module "$5" \
        "${@:6}"
