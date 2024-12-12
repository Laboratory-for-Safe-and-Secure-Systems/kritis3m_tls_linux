#!/bin/bash

if [ "$#" -lt 2 ]; then
	echo "Invalid argument count: needs at least 2 (<port> destination, <cert_dir>)" >&2
	exit 2
fi

echo -e "Starting KRITIS3M TLS server on port $1 with certs in dir $2\r"
kritis3m_tls echo_server \
	--incoming "$1" \
	--root "$2"/root.pem \
	--cert "$2"/chain.pem \
	--key "$2"/privateKey.pem \
	"${@:3}"
