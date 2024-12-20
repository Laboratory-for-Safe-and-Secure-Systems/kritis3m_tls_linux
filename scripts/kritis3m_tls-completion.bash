#!/usr/bin/env bash

# Help print
#
# Usage: kritis3m_tls ROLE [OPTIONS]
# Roles:
#   reverse_proxy                  TLS reverse proxy (use "--incoming" and "--outgoing" for connection configuration)
#   forward_proxy                  TLS forward proxy (use "--incoming" and "--outgoing" for connection configuration)
#   echo_server                    TLS echo server (use "--incoming" for connection configuration)
#   echo_server_proxy              TLS echo server via reverse proxy (use "--incoming" for connection configuration)
#   tls_client                     TLS stdin client (use "--outgoing" for connection configuration)
#   network_tester                 TLS network tester (use "--outgoing" for connection configuration)
#   network_tester_proxy           TLS network tester via forward proxy (use "--outgoing" for connection configuration)
#   management_client              Management Client (use "--mgmt_path to provide config file path)
#
# Connection configuration:
#   --incoming <ip:>port           Configuration of the incoming TCP/TLS connection
#   --outgoing ip:port             Configuration of the outgoing TCP/TLS connection
#
# Certificate/Key configuration:
#   --cert file_path               Path to the certificate file
#   --key file_path                Path to the private key file
#   --intermediate file_path       Path to an intermediate certificate file
#   --root file_path               Path to the root certificate file
#   --additional_key file_path     Path to an additional private key file (hybrid certificate)
#
# Security configuration:
#   --no_mutual_auth               Disable mutual authentication (default enabled)
#   --use_null_cipher              Use a cleartext cipher without encryption (default disabled)
#   --key_exchange_alg algorithm   Key exchange algorithm: (default: "secp384_mlkem768")
#                                     Classic: "secp256", "secp384", "secp521", "x25519", "x448"
#                                     PQC: "mlkem512", "mlkem768", "mlkem1024"
#                                     Hybrid: "secp256_mlkem512", "secp384_mlkem768", "secp256_mlkem768"
#                                             "secp521_mlkem1024", "secp384_mlkem1024", "x25519_mlkem512"
#                                             "x448_mlkem768", "x25519_mlkem768"
#
# PKCS#11:
#   When using a secure element for long-term key storage, you have to supply the PKCS#11 key labels using the
#   arguments "--key" and "--additionalKey", prepending the string "pkcs11:" followed by the key label.
#   As an alternative, the file provided by "--key" and "--additionalKey" may also contain the key label with
#   the same identifier before it. In this case, the label must be the first line of the file.
#   --pkcs11_module file_path      Path to the secure element middleware for long-term key storage
#   --pkcs11_pin pin               PIN for the secure element (default empty)
#   --pkcs11_crypto_all            Use the PKCS#11 module for all supported crypto operations (default disabled)
#
# Network tester configuration:
#   --test_num_handshakes num      Number of handshakes to perform in the test (default 1)
#   --test_handshake_delay num_ms  Delay between handshakes in milliseconds (default 0)
#   --test_num_messages num        Number of echo messages to send per handshake iteration (default 0)
#   --test_message_delay num_us    Delay between messages in microseconds (default 0)
#   --test_message_size num        Size of the echo message in bytes (default 1)
#   --test_output_path path        Path to the output file (filename will be appended)
#   --test_no_tls                  Disable TLS for test (plain TCP; default disabled)
#   --test_silent                  Disable progress printing
#
# Management:
#   --mgmt_path                    Path to management config
#
# General:
#   --keylog_file file_path        Path to the keylog file for Wireshark
#   --verbose                      Enable verbose output
#   --debug                        Enable debug output
#   --help                         Display this help and exit

_kritis3m_tls_completions() {
        local cur prev roles opts_connection opts_files opts_security opts_tester opts_general hybrid_modes kex_algos

        COMPREPLY=()

        _get_comp_words_by_ref -n : cur
        _get_comp_words_by_ref -n : prev

        roles="reverse_proxy forward_proxy echo_server echo_server_proxy tls_client network_tester network_tester_proxy management_client"
        opts_connection="--incoming --outgoing"
        opts_files="--cert --key --intermediate --root --additional_key --pkcs11_module --keylog_file"
        opts_security="--no_mutual_auth --use_null_cipher --key_exchange_alg --pkcs11_pin --pkcs11_crypto_all"
        opts_tester="--test_num_handshakes --test_handshake_delay --test_num_messages --test_message_delay --test_message_size \
                        --test_output_path --test_no_tls --test_silent"
        opts_mgmt="--mgmt_path"
        opts_general="--verbose --debug --help"

        kex_algos="secp256 secp384 secp521 x25519 x448 mlkem512 mlkem768 mlkem1024
                   secp256_mlkem512 secp384_mlkem768 secp256_mlkem768 secp521_mlkem1024
                   secp384_mlkem1024 x25519_mlkem512 x448_mlkem768 x25519_mlkem768"

        if [[ ${COMP_CWORD} -eq 1 ]]; then
                COMPREPLY=($(compgen -W "${roles}" -- ${cur}))
                return 0
        fi

        if [[ ${cur} == -* ]]; then
                COMPREPLY=($(compgen -W "${opts_connection} ${opts_files} ${opts_security} ${opts_tester} ${opts_mgmt} ${opts_general}" -- ${cur}))
                return 0
        fi

        case "${prev}" in
        reverse_proxy | forward_proxy | echo_server | echo_server_proxy | tls_client | network_tester | network_tester_proxy | management_client)
                COMPREPLY=($(compgen -W "${opts_connection} ${opts_files} ${opts_security} ${opts_tester} ${opts_mgmt} ${opts_general}" -- ${cur}))
                return 0
                ;;
        --incoming | --outgoing)
                COMPREPLY=($(compgen -W "ip:port port" -- ${cur}))
                return 0
                ;;
        --cert | --key | --intermediate | --root | --additional_key | --pkcs11_module | --keylog_file | --test_output_path | --mgmt_path)
                _filedir
                return 0
                ;;
        --key_exchange_alg)
                COMPREPLY=($(compgen -W "${kex_algos}" -- ${cur}))
                return 0
                ;;
        --no_mutual_auth | --use_null_cipher | --test_num_handshakes | --test_handshake_delay | --test_num_messages | --test_message_delay | --test_message_size | \
                --test_no_tls | --test_silent | --pkcs11_pin | pkcs11_crypto_all)
                # No specific completion
                COMPREPLY=()
                return 0
                ;;
        *)
                COMPREPLY=($(compgen -W "${opts_connection} ${opts_files} ${opts_security} ${opts_tester} ${opts_general}" -- ${cur}))
                return 0
                ;;
        esac
}

_proxy_helper_completions() {
        local cur prev
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
        local cur prev
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
complete -F _endpoint_helper_completions kritis3m_echo_server_proxy
complete -F _endpoint_helper_completions kritis3m_tls_client
complete -F _endpoint_helper_completions kritis3m_network_tester
complete -F _endpoint_helper_completions kritis3m_network_tester_proxy
