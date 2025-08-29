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
#   --ciphersuites suites          Use given TLS1.3 ciphersuites, separated by ":". For clients, the first one is selected
#                                     for the connection. Default is: "TLS13-AES256-GCM-SHA384:TLS13-SHA384-SHA384"
#   --key_exchange_alg algorithm   Key exchange algorithm: (default: "secp384_mlkem768")
#                                     Classic: "secp256", "secp384", "secp521", "x25519", "x448"
#                                     PQC: "mlkem512", "mlkem768", "mlkem1024"
#                                     Hybrid: "secp256_mlkem512", "secp384_mlkem768", "secp256_mlkem768"
#                                             "secp521_mlkem1024", "secp384_mlkem1024", "x25519_mlkem512"
#                                             "x448_mlkem768", "x25519_mlkem768"
#
# Pre-shared keys:
#   --pre_shared_key id:key        Pre-shared key and identity to use. The identity is sent from client to server during
#                                     the handshake. The key has to be Base64 encoded.
#   --psk_no_kex                   Disable (EC)DHE key generation in addition to the PSK shared secret
#   --psk_no_cert_auth             Disable certificates in addition to the PSK for peer authentication
#   --psk_pre_extracted            HKDF-Extract operation is already performed, only the Expand part is necessary
#
# QKD:
#   When using QKD in the TLS applications, you have to specify this in the --pre_shared_key parameter.
#   In that case, two modes are possible:
#       --pre_shared_key "qkd"         Use a HTTP request to the QKD key magament system.
#       --pre_shared_key "qkd:secure"  Use a secured HTPPS request to the QKD key management system.
#                                           In this mode, the qkd_xxx arguments below must be set.
#
#   --qkd_cert file_path           Path to the certificate file used for the HTTPS connection to the QKD server
#   --qkd_root file_path           Path to the root certificate file used for the HTTPS connection to the QKD server
#   --qkd_key file_path            Path to the private key file used for the HTTPS connection to the QKD server
#   --qkd_psk id:key               Pre-shared key and identity to use for the HTTPS connectionto the QKD server.
#                                     The key has to be Base64 encoded.
#
# PKCS#11:
#   When using a PKCS#11 token for key/cert storage, you have to supply the PKCS#11 labels using the arguments
#   "--key","--additionalKey", and "--cert", prepending the string "pkcs11:" followed by the label.
#   As an alternative, the file provided by "--key", "--additionalKey" or "--cert" may also contain the key label with
#   the same identifier before it. In this case, the label must be the first line of the file.
#
#   To use a pre-shared key on a PKCS#11 token, the "--pre_shared_key" arguement is used: instead of a Base64
#   encoded key, the label "pkcs11" has to be specified. In this case, the given PSK identity is used as
#   the PKCS#11 label of the pre-shared key on the token.
#
#   --pkcs11_module file_path      Path to the PKCS#11 token middleware
#   --pkcs11_pin pin               PIN for the token (default empty)
#   --pkcs11_crypto_all            Use the PKCS#11 token for all supported crypto operations (default disabled)
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
        local cur prev roles opts_connection opts_files opts_security opts_tester opts_general kex_algos

        COMPREPLY=()

        _get_comp_words_by_ref -n : cur
        _get_comp_words_by_ref -n : prev

        roles="reverse_proxy forward_proxy echo_server echo_server_proxy tls_client network_tester network_tester_proxy management_client"
        opts_connection="--incoming --outgoing"
        opts_files="--cert --key --intermediate --root --additional_key --pkcs11_module --keylog_file --pre_shared_key --qkd_cert \
                        --qkd_root --qkd_key --qkd_psk"
        opts_security="--no_mutual_auth --ciphersuites --key_exchange_alg --psk_no_kex --psk_no_cert_auth --psk_pre_extracted \
                        --pkcs11_pin --pkcs11_slot_id --pkcs11_crypto_all --qkd_node --qkd_own_sae_id --qkd_remote_sae_id"
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
        --cert | --key | --intermediate | --root | --additional_key | --pkcs11_module | --keylog_file | --test_output_path | --mgmt_path | --pre_shared_key | \
                --qkd_cert | --qkd_root | --qkd_key | --qkd_psk)
                _filedir
                return 0
                ;;
        --key_exchange_alg)
                COMPREPLY=($(compgen -W "${kex_algos}" -- ${cur}))
                return 0
                ;;
        --no_mutual_auth | --ciphersuites | --psk_no_kex | --psk_no_cert_auth | --psk_pre_extracted | \
                --qkd_node | --qkd_own_sae_id | --qkd_remote_sae_id | \
                --test_num_handshakes | --test_handshake_delay | --test_num_messages | --test_message_delay | --test_message_size | --test_no_tls | \
                --test_silent | \
                --pkcs11_pin | --pkcs11_slot_id | pkcs11_crypto_all)
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
