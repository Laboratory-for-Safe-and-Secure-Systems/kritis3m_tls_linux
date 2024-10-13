# Check if the number of arguments is less than 2
if ($Args.Count -lt 2) {
        Write-Host "Invalid argument count: needs at least 2 (<port> destination, <cert_dir>)" -ForegroundColor Red
        exit 2
}

# Output message
Write-Host "Starting KRITIS3M TLS server on port $($Args[0]) with certs in dir $($Args[1])`r"

# Run the kritis3m_tls echo_server command with the provided arguments
kritis3m_tls echo_server `
        --incoming $Args[0] `
        --root "$($Args[1])/root/cert.pem" `
        --cert "$($Args[1])/server/chain.pem" `
        --key "$($Args[1])/server/privateKey.pem" `
        $Args[2..$Args.Count]  # Pass any additional arguments
