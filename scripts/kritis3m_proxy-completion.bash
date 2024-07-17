#/usr/bin/env bash

# Help print
#
# Usage: kritis3m_proxy ROLE [OPTIONS]
# Roles:
#
#   reverse_proxy                    TLS reverse proxy (use --incoming and --outgoing for connection configuration)
#   forward_proxy                    TLS forward proxy (use --incoming and --outgoing for connection configuration)
#   echo_server                      TLS echo server (use --incoming for connection configuration)
#   echo_client                      TLS stdin client (use --outgoing for connection configuration)
#
# Connection configuration:
#
#   --incoming <ip:>port             configuration of the incoming TCP/TLS connection
#   --outgoing ip:port               configuration of the outgoing TCP/TLS connection
#
# Options:
#
#   --cert file_path                 path to the certificate file
#   --key file_path                  path to the private key file
#   --intermediate file_path         path to an intermediate certificate file
#   --root file_path                 path to the root certificate file
#   --additionalKey file_path        path to an additional private key file (hybrid signature mode)
#
#   --mutualAuth 0|1                 enable or disable mutual authentication (default enabled)
#   --noEncryption 0|1               enable or disable encryption (default enabled)
#   --hybrid_signature mode          mode for hybrid signatures: both, native, alternative (default: both)
#
#   --use_secure_element 0|1         use secure element (default disabled)
#   --middleware_path file_path      path to the secure element middleware
#   --se_import_keys 0|1             import provided keys into secure element (default disabled)
#
#   --verbose                        enable verbose output
#   --debug                          enable debug output
#   --keylogFile file_path           path to the keylog file for Wireshark
#
#   --help                           display this help and exit


_kritis3m_proxy_completions()
{
        local cur prev roles opts_connection opts_files opts_bools opts_hybrid opts_general

        COMPREPLY=()

        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"

        roles="reverse_proxy forward_proxy echo_server tls_client"
        opts_connection="--incoming --outgoing"
        opts_files="--cert --key --intermediate --root --additionalKey --middleware_path --keylogFile"
        opts_bools="--mutualAuth --noEncryption --use_secure_element --se_import_keys"
        opts_hybrid="--hybrid_signature"
        opts_general="--verbose --debug --help"

        if [[ ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${roles}" -- ${cur}) )
                return 0
        fi

        if [[ ${cur} == -* ]]; then
                COMPREPLY=( $(compgen -W "${opts_connection} ${opts_files} ${opts_bools} ${opts_hybrid} ${opts_general}" -- ${cur}) )
                return 0
        fi

        case "${prev}" in
                reverse_proxy|forward_proxy|echo_server|tls_client)
                        COMPREPLY=( $(compgen -W "${opts_connection} ${opts_files} ${opts_bools} ${opts_hybrid} ${opts_general}" -- ${cur}) )
                        return 0
                        ;;
                --incoming|--outgoing)
                        COMPREPLY=( $(compgen -W "ip:port port" -- ${cur}) )
                        return 0
                        ;;
                --cert|--key|--intermediate|--root|--additionalKey|--middleware_path|--keylogFile)
                        _filedir
                        return 0
                        ;;
                --hybrid_signature)
                        COMPREPLY=( $(compgen -W "both native alternative" -- ${cur}) )
                        return 0
                        ;;
                --mutualAuth|--noEncryption|--use_secure_element|--se_import_keys)
                        COMPREPLY=( $(compgen -W "0 1" -- ${cur}) )
                        return 0
                        ;;
                *)
                        COMPREPLY=( $(compgen -W "${opts_connection} ${opts_files} ${opts_bools} ${opts_hybrid} ${opts_general}" -- ${cur}) )
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
        # Pass the remaining arguments to the kritis3m_proxy completion function
        _kritis3m_proxy_completions
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
        # Pass the remaining arguments to the kritis3m_proxy completion function
        _kritis3m_proxy_completions
    fi
}

complete -F _kritis3m_proxy_completions kritis3m_proxy

complete -F _proxy_helper_completions kritis3m_forward_proxy
complete -F _proxy_helper_completions kritis3m_reverse_proxy
complete -F _endpoint_helper_completions kritis3m_echo_server
complete -F _endpoint_helper_completions kritis3m_tls_client
