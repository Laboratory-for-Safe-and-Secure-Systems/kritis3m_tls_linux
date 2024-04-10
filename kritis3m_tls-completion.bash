#/usr/bin/env bash

# Help print
# Usage: ./kritis3m_tls [OPTIONS]
# Roles:
#
#   --reverse_proxy                  start a TLS reverse proxy (use --incoming and --outgoing for connection configuration)
#   --forward_proxy                  start a TLS forward proxy (use --incoming and --outgoing for connection configuration)
#   --echo_server                    start a TLS echo server (use --incoming for connection configuration)
#   --echo_client                    start a TLS stdin echo client (use --outgoing for connection configuration)
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
#   --debug                          enable debug output
#   --keylogFile file_path           path to the keylog file for Wireshark
#
#   --bridge_lan interface           name of the LAN interface for the Layer 2 bridge
#   --bridge_wan interface           name of the WAN interface for the Layer 2 bridge
#
#   --help                           display this help and exit

_kritis3m_tls_completions()
{
    local cur prev opts_roles opts_connection opts_files opts_bools opts_hybrid opts_general

    COMPREPLY=()

    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts_roles="--reverse_proxy --forward_proxy --echo_server --echo_client"
    opts_connection="--incoming --outgoing"
    opts_files="--cert --key --intermediate --root --additionalKey --middleware_path --keylogFile"
    opts_bools="--mutualAuth --noEncryption --use_secure_element --se_import_keys"
    opts_hybrid="--hybrid_signature"
    opts_general="--verbose --debug --help"
    if [[ ${cur} == -* ]]; then
	COMPREPLY=( $(compgen -W "${opts_roles} ${opts_connection} ${opts_files} ${opts_bools} ${opts_hybrid} ${opts_general}" -- ${cur}) )
	return 0
    fi
    case "${prev}" in
	--reverse_proxy|--forward_proxy|--echo_server|--echo_client)
	    COMPREPLY=( $(compgen -W "${opts_connection} ${opts_files} ${opts_bools} ${opts_hybrid} ${opts_general}" -- ${cur}) )
	    return 0
	    ;;
	--incoming|--outgoing)
	    COMPREPLY=( $(compgen -W "ip:port port" -- ${cur}) )
	    return 0
	    ;;
	--cert|--key|--intermediate|--root|--additionalKey|--middleware_path|--keylogFile)
	    COMPREPLY=( $(compgen -f -- ${cur}) )
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
	    COMPREPLY=( $(compgen -W "${opts_roles} ${opts_connection} ${opts_files} ${opts_bools} ${opts_hybrid} ${opts_general}" -- ${cur}) )
	    return 0
	    ;;
    esac
}

complete -F _kritis3m_tls_completions kritis3m_tls
