#/usr/bin/env bash

# Help print
#
# Usage: kritis3m_tls ROLE [OPTIONS]
# Roles:
#   reverse_proxy                    TLS reverse proxy (use "--incoming" and "--outgoing" for connection configuration)
#   forward_proxy                    TLS forward proxy (use "--incoming" and "--outgoing" for connection configuration)
#   echo_server                      TLS echo server (use "--incoming" for connection configuration)
#   tls_client                       TLS stdin client (use "--outgoing" for connection configuration)
#   network_tester                   TLS network tester (use "--outgoing" for connection configuration)
#
# Connection configuration:
#   --incoming <ip:>port             configuration of the incoming TCP/TLS connection
#   --outgoing ip:port               configuration of the outgoing TCP/TLS connection
#
# Certificate/Key configuration:
#   --cert file_path                 path to the certificate file
#   --key file_path                  path to the private key file
#   --intermediate file_path         path to an intermediate certificate file
#   --root file_path                 path to the root certificate file
#   --additionalKey file_path        path to an additional private key file (hybrid signature mode)
#
# Security configuration:
#   --mutualAuth 0|1                 enable or disable mutual authentication (default enabled)
#   --noEncryption 0|1               enable or disable encryption (default enabled)
#   --hybrid_signature mode          mode for hybrid signatures: "both", "native", "alternative" (default: "both")
#   --keyExchangeAlg algorithm       key exchange algorithm: (default: "secp384_mlkem768")
#                                       classic: "secp256", "secp384", "secp521", "x25519", "x448"
#                                       PQC: "mlkem512", "mlkem768", "mlkem1024"
#                                       hybrid: "secp256_mlkem512", "secp384_mlkem768", "secp256_mlkem768"
#                                               "secp521_mlkem1024", "secp384_mlkem1024", "x25519_mlkem512"
#                                               "x448_mlkem768", "x25519_mlkem768"
# Secure Element:
#   When using a secure element for key storage, you have to supply the PKCS#11 key labels using the arguments
#   "--key" and "--additionalKey" prepending the string "pkcs11:" followed by the key label.
#   --middleware file_path           path to the secure element middleware
#
# Network tester configuration:
#   --test_iterations num            Number of handshakes to perform in the test
#   --test_delay num_ms              Delay between handshakes in milliseconds
#   --test_output_path path          Path to the output file (filename will be appended)
#   --test_tls 0|1                   enable or disable TLS (default disabled)
#
# General:
#   --keylogFile file_path           path to the keylog file for Wireshark
#   --verbose                        enable verbose output
#   --debug                          enable debug output
#   --help                           display this help and exit
#


_kritis3m_tls_completions()
{
        local cur prev roles opts_connection opts_files opts_security opts_tester opts_general hybrid_modes kex_algos

        COMPREPLY=()

        _get_comp_words_by_ref -n : cur
        _get_comp_words_by_ref -n : prev

        roles="reverse_proxy forward_proxy echo_server tls_client network_tester"
        opts_connection="--incoming --outgoing"
        opts_files="--cert --key --intermediate --root --additionalKey --middleware --keylogFile"
        opts_security="--mutualAuth --noEncryption --hybrid_signature --keyExchangeAlg"
        opts_tester="--test_iterations --test_delay --test_output_path --test_tls"
        opts_general="--verbose --debug --help"

        hybrid_modes="both native alternative"
        kex_algos="secp256 secp384 secp521 x25519 x448 mlkem512 mlkem768 mlkem1024
                   secp256_mlkem512 secp384_mlkem768 secp256_mlkem768 secp521_mlkem1024
                   secp384_mlkem1024 x25519_mlkem512 x448_mlkem768 x25519_mlkem768"

        if [[ ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${roles}" -- ${cur}) )
                return 0
        fi

        if [[ ${cur} == -* ]]; then
                COMPREPLY=( $(compgen -W "${opts_connection} ${opts_files} ${opts_security} ${opts_tester} ${opts_general}" -- ${cur}) )
                return 0
        fi

        case "${prev}" in
                reverse_proxy|forward_proxy|echo_server|tls_client|network_tester)
                        COMPREPLY=( $(compgen -W "${opts_connection} ${opts_files} ${opts_security} ${opts_tester} ${opts_general}" -- ${cur}) )
                        return 0
                        ;;
                --incoming|--outgoing)
                        COMPREPLY=( $(compgen -W "ip:port port" -- ${cur}) )
                        return 0
                        ;;
                --cert|--key|--intermediate|--root|--additionalKey|--middleware|--keylogFile|--test_output_path)
                        _filedir
                        return 0
                        ;;
                --hybrid_signature)
                        COMPREPLY=( $(compgen -W "${hybrid_modes}" -- ${cur}) )
                        return 0
                        ;;
                --keyExchangeAlg)
                        COMPREPLY=( $(compgen -W "${kex_algos}" -- ${cur}) )
                        return 0
                        ;;
                --mutualAuth|--noEncryption|--test_tls)
                        COMPREPLY=( $(compgen -W "0 1" -- ${cur}) )
                        return 0
                        ;;
                --test_iterations|--test_delay)
                        # No specific completion
                        COMPREPLY=()
                        return 0
                        ;;
                *)
                        COMPREPLY=( $(compgen -W "${opts_connection} ${opts_files} ${opts_security} ${opts_tester} ${opts_general}" -- ${cur}) )
                        return 0
                        ;;
        esac
}

_proxy_helper_completions() {
    local cur prev opts
    COMPREPLY=()

    _get_comp_words_by_ref -n : cur
    _get_comp_words_by_ref -n : prev

    # The helper script needs at least 3 arguments: <ip:port> in, <ip:port> out, <cert_dir>
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        # The first argument should be the incoming <ip:port>
        COMPREPLY=()
        return 0
    elif [[ ${COMP_CWORD} -eq 2 ]]; then
        # The second argument should be the outgoing <ip:port>
        COMPREPLY=()
        return 0
    elif [[ ${COMP_CWORD} -eq 3 ]]; then
        # The third argument should be the <cert_dir>
        _filedir
        return 0
    else
        # Pass the remaining arguments to the kritis3m_tls completion function
        _kritis3m_tls_completions
    fi
}

_endpoint_helper_completions() {
    local cur prev opts
    COMPREPLY=()

    _get_comp_words_by_ref -n : cur
    _get_comp_words_by_ref -n : prev

    # The helper script needs at least 2 arguments: <ip:port> endpoint, <cert_dir>
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        # The first argument should be the network endpoint <ip:port>
        COMPREPLY=()
        return 0
    elif [[ ${COMP_CWORD} -eq 2 ]]; then
        # The second argument should be the <cert_dir>
        _filedir
        return 0
    else
        # Pass the remaining arguments to the kritis3m_tls completion function
        _kritis3m_tls_completions
    fi
}

complete -F _kritis3m_tls_completions kritis3m_tls

complete -F _proxy_helper_completions kritis3m_forward_proxy
complete -F _proxy_helper_completions kritis3m_reverse_proxy
complete -F _endpoint_helper_completions kritis3m_echo_server
complete -F _endpoint_helper_completions kritis3m_tls_client
complete -F _endpoint_helper_completions kritis3m_network_tester_tls
