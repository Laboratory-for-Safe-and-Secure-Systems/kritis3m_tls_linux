# Check if the number of arguments is less than 3
if ($Args.Count -lt 4) {
        Write-Host "Invalid argument count: needs at least 4 (<port> destination, <cert_dir>, <label> of PKCS#11 private key, <path> PKCS#11 middleware)" -ForegroundColor Red
        exit 2
}

# Output message
Write-Host "Starting KRITIS3M TLS server on port $($Args[0]) with certs in dir $($Args[1]) and PKCS#11 private key with label ""$($Args[2])""`r"

# Prepend the PKCS#11 identifier ("pkcs11:") to the provided key label
$pkcs11_label = "pkcs11:$($Args[2])"

# Run the kritis3m_tls echo_server command with the provided arguments
kritis3m_tls echo_server `
        --incoming $Args[0] `
        --root "$($Args[1])/root/cert.pem" `
        --cert "$($Args[1])/server/chain.pem" `
        --key $pkcs11_label `
        --p11_long_term_module $Args[3] `
        $Args[4..$Args.Count]  # Pass any additional arguments
