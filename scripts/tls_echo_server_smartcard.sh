#!/bin/bash

if [ "$#" -lt 4 ]; then
	echo "Invalid argument count: needs at least 4 (<port> destination, <cert_dir>, <label> of PKCS#11 private key, <path> PKCS#11 middleware)" >&2
	exit 2
fi

echo -e "Starting KRITIS3M TLS server on port $1 with certs in dir $2\r"
kritis3m_tls echo_server \
	--incoming "$1" \
	--root "$2"/root.pem \
	--cert "$2"/chain.pem \
	--key pkcs11:"$3" \
	--pkcs11_module "$4" \
	"${@:5}"
