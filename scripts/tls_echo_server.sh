#!/bin/bash

if [ "$#" -lt 2 ]; then
	echo "Invalid argument count: needs at least 2 (<port> destination, <cert_dir>)" >&2
	exit 2
fi


echo "Starting KRITIS3M TLS server on port $1 with certs in dir $2"
kritis3m_tls echo_server \
	--incoming $1 \
	--root $2/root/cert.pem \
	--cert $2/server/chain.pem \
	--key $2/server/privateKey.pem \
	${@:3}

