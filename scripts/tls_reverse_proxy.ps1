# Check if the number of arguments is less than 3
if ($Args.Count -lt 3) {
        Write-Host "Invalid argument count: needs at least 3 (<ip:port> in, <ip:port> out, <cert_dir>)" -ForegroundColor Red
        exit 2
}

# Output message
Write-Host "Starting KRITIS3M TLS-TCP Reverse Proxy from $($Args[0]) to $($Args[1]) with certs in $($Args[2])`r"

# Run the kritis3m_tls reverse_proxy command with the provided arguments
kritis3m_tls proxy `
        --incoming "tls://$($Args[0])" `
        --outgoing "tcp://$($Args[1])" `
        --root "$($Args[2])/root/cert.pem" `
        --cert "$($Args[2])/server/chain.pem" `
        --key "$($Args[2])/server/privateKey.pem" `
        $Args[3..$Args.Count]  # Pass any additional arguments
