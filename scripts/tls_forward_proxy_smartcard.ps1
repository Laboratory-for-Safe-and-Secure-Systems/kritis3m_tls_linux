# Check if the number of arguments is less than 5
if ($Args.Count -lt 5) {
        Write-Host "Invalid argument count: needs at least 5 (<ip:port> in, <ip:port> out, <cert_dir>, <label> of PKCS#11 private key, <path> PKCS#11 middleware)" -ForegroundColor Red
        exit 2
}

# Output message
Write-Host "Starting KRITIS3M TLS Forward Proxy from $($Args[0]) to $($Args[1]) with certs in $($Args[2])`r"

# Prepend the PKCS#11 identifier ("pkcs11:") to the provided key label
$pkcs11_label = "pkcs11:$($Args[3])"

# Run the kritis3m_tls forward_proxy command with the provided arguments
kritis3m_tls forward_proxy `
        --incoming $Args[0] `
        --outgoing $Args[1] `
        --root "$($Args[2])/root/cert.pem" `
        --cert "$($Args[2])/server/chain.pem" `
        --key $pkcs11_label `
        --p11_long_term_module $Args[4] `
        $Args[5..$Args.Count]  # Pass any additional arguments
