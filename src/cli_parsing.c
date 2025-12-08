#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include "cli_parsing.h"
#include "file_io.h"
#include "logging.h"
#include "networking.h"

LOG_MODULE_CREATE(cli_parsing);

static const struct option cli_options[] = {
        {"incoming", required_argument, 0, 0x01},
        {"outgoing", required_argument, 0, 0x02},

        {"cert", required_argument, 0, 0x03},
        {"key", required_argument, 0, 0x04},
        {"intermediate", required_argument, 0, 0x05},
        {"root", required_argument, 0, 0x06},
        {"additional_key", required_argument, 0, 0x07},

        {"no_mutual_auth", no_argument, 0, 0x08},
        {"ciphersuites", required_argument, 0, 0x09},
        {"key_exchange_alg", required_argument, 0, 0x0B},
        {"pre_shared_key", required_argument, 0, 0x0A},
        {"psk_no_cert_auth", no_argument, 0, 0x19},
        {"psk_no_kex", no_argument, 0, 0x23},
        {"psk_pre_extracted", no_argument, 0, 0x25},

        {"qkd_node", required_argument, 0, 0x26},
        {"qkd_own_sae_id", required_argument, 0, 0x27},
        {"qkd_remote_sae_id", required_argument, 0, 0x28},
        {"qkd_cert", required_argument, 0, 0x20},
        {"qkd_key", required_argument, 0, 0x21},
        {"qkd_root", required_argument, 0, 0x22},
        {"qkd_psk", required_argument, 0, 0x24},

        {"pkcs11_module", required_argument, 0, 0x0C},
        {"pkcs11_pin", required_argument, 0, 0x0D},
        {"pkcs11_slot_id", required_argument, 0, 0x29},
        {"pkcs11_crypto_all", no_argument, 0, 0x0E},

        {"test_num_handshakes", required_argument, 0, 0x0F},
        {"test_handshake_delay", required_argument, 0, 0x10},
        {"test_num_messages", required_argument, 0, 0x11},
        {"test_message_delay", required_argument, 0, 0x12},
        {"test_message_size", required_argument, 0, 0x13},
        {"test_output_path", required_argument, 0, 0x14},
        {"test_name", required_argument, 0, 0x30},
        {"test_no_tls", no_argument, 0, 0x15},
        {"test_silent", no_argument, 0, 0x16},

        {"keylog_file", required_argument, 0, 0x17},

        {"mgmt_path", required_argument, 0, 0x18},

        {"in_cert", required_argument, 0, 0x31},
        {"in_key", required_argument, 0, 0x32},
        {"in_intermediate", required_argument, 0, 0x33},
        {"in_root", required_argument, 0, 0x34},
        {"in_additional_key", required_argument, 0, 0x35},
        {"in_no_mutual_auth", no_argument, 0, 0x36},
        {"in_ciphersuites", required_argument, 0, 0x37},
        {"in_key_exchange_alg", required_argument, 0, 0x38},
        {"in_pre_shared_key", required_argument, 0, 0x39},
        {"in_psk_no_cert_auth", no_argument, 0, 0x3A},
        {"in_psk_no_kex", no_argument, 0, 0x3B},
        {"in_psk_pre_extracted", no_argument, 0, 0x3C},
        {"in_pkcs11_module", required_argument, 0, 0x49},
        {"in_pkcs11_pin", required_argument, 0, 0x4A},
        {"in_pkcs11_slot_id", required_argument, 0, 0x4B},
        {"in_pkcs11_crypto_all", no_argument, 0, 0x4C},
        {"in_keylog_file", required_argument, 0, 0x4D},

        {"out_cert", required_argument, 0, 0x3D},
        {"out_key", required_argument, 0, 0x3E},
        {"out_intermediate", required_argument, 0, 0x3F},
        {"out_root", required_argument, 0, 0x40},
        {"out_additional_key", required_argument, 0, 0x41},
        {"out_no_mutual_auth", no_argument, 0, 0x42},
        {"out_ciphersuites", required_argument, 0, 0x43},
        {"out_key_exchange_alg", required_argument, 0, 0x44},
        {"out_pre_shared_key", required_argument, 0, 0x45},
        {"out_psk_no_cert_auth", no_argument, 0, 0x46},
        {"out_psk_no_kex", no_argument, 0, 0x47},
        {"out_psk_pre_extracted", no_argument, 0, 0x48},
        {"out_pkcs11_module", required_argument, 0, 0x4E},
        {"out_pkcs11_pin", required_argument, 0, 0x4F},
        {"out_pkcs11_slot_id", required_argument, 0, 0x50},
        {"out_pkcs11_crypto_all", no_argument, 0, 0x51},
        {"out_keylog_file", required_argument, 0, 0x52},

        {"verbose", no_argument, 0, 'v'},
        {"debug", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},

        {NULL, 0, NULL, 0},
};

extern unsigned int asl_psk_client_callback(char* key, char* identity, void* ctx);
extern unsigned int asl_psk_server_callback(char* key, char* identity, void* ctx);

static int check_pre_shared_key(asl_endpoint_configuration* tls_config, application_config* app_config);
static int check_qkd_config(quest_configuration* quest_config,
                            asl_endpoint_configuration* qkd_config,
                            asl_endpoint_configuration* tls_config,
                            application_config* app_config,
                            char* qkd_protocol);
static void print_help(char const* name);

/* Parse the provided argv array and store the information in the provided config variables.
 *
 * Returns 0 on success, +1 in case the help was printed and  -1 on failure (error is printed on console).
 */
int parse_cli_arguments(application_config* app_config,
                        proxy_backend_config* proxy_backend_config,
                        proxy_config* proxy_config,
                        echo_server_config* echo_server_config,
                        network_tester_config* tester_config,
                        quest_configuration* quest_config,
                        char** mgmt_config_path,
                        size_t argc,
                        char** argv)
{
        if ((app_config == NULL) || (proxy_backend_config == NULL) || (proxy_config == NULL) ||
            (tester_config == NULL) || (echo_server_config == NULL))
        {
                LOG_ERROR("parse_cli_arguments() mustn't be called with a NULL pointer");
                return -1;
        }
        else if (argc < 2)
        {
                print_help(argv[0]);
                return 1;
        }

        char* incoming_ip = NULL;
        uint16_t incoming_port = 0;
        char* incoming_protocol = NULL;

        char* outgoing_ip = NULL;
        uint16_t outgoing_port = 0;
        char* outgoing_protocol = NULL;

        char* qkd_protocol = NULL;

        certificates certs = get_empty_certificates();
        asl_endpoint_configuration tls_config = asl_default_endpoint_config();

        certificates in_certs = get_empty_certificates();
        asl_endpoint_configuration in_tls_config = asl_default_endpoint_config();

        certificates out_certs = get_empty_certificates();
        asl_endpoint_configuration out_tls_config = asl_default_endpoint_config();

        /* TLS config for HTTPS connection to the QKD line */
        certificates qkd_certs = get_empty_certificates();
        asl_endpoint_configuration qkd_config = asl_default_endpoint_config();

        /* Application config */
        app_config->role = NOT_SET;
        app_config->log_level = LOG_LVL_WARN;

        /* Parse role */
        if (strcmp(argv[1], "proxy") == 0)
        {
                app_config->role = ROLE_PROXY;
        }
        else if (strcmp(argv[1], "echo_server") == 0)
        {
                app_config->role = ROLE_ECHO_SERVER;
        }
        else if (strcmp(argv[1], "echo_server_proxy") == 0)
        {
                app_config->role = ROLE_ECHO_SERVER_PROXY;
        }
        else if (strcmp(argv[1], "tls_client") == 0)
        {
                app_config->role = ROLE_TLS_CLIENT;
        }
        else if (strcmp(argv[1], "network_tester") == 0)
        {
                app_config->role = ROLE_NETWORK_TESTER;
        }
        else if (strcmp(argv[1], "network_tester_proxy") == 0)
        {
                app_config->role = ROLE_NETWORK_TESTER_PROXY;
        }
        else if (strcmp(argv[1], "management_client") == 0)
        {
                app_config->role = ROLE_MANAGEMENT_CLIENT;
        }
        else if ((strcmp(argv[1], "-h") == 0) || (strcmp(argv[1], "--help") == 0))
        {
                print_help(argv[0]);
                return 1;
        }
        else
        {
                LOG_ERROR("invalid role: %s", argv[1]);
                print_help(argv[0]);
                return 1;
        }

        /* Parse arguments */
        int index = 0;
        while (true)
        {
                int result = getopt_long(argc, argv, "vdh", cli_options, &index);

                if (result == -1)
                        break; /* end of list */

                switch (result)
                {
                case 0x01: /* incoming */
                        if (parse_ip_address(optarg, &incoming_ip, &incoming_port, &incoming_protocol) !=
                            0)
                        {
                                LOG_ERROR("unable to parse incoming IP address");
                                return -1;
                        }
                        break;
                case 0x02: /* outgoing */
                        if (parse_ip_address(optarg, &outgoing_ip, &outgoing_port, &outgoing_protocol) !=
                            0)
                        {
                                LOG_ERROR("unable to parse outgoing IP address");
                                return -1;
                        }
                        if (outgoing_port == 0)
                        {
                                LOG_ERROR("outgoing port must not be 0");
                                return -1;
                        }
                        break;
                case 0x03: /* cert */
                        certs.certificate_path = duplicate_string(optarg);
                        if (certs.certificate_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for certificate");
                                return -1;
                        }
                        break;
                case 0x04: /* key */
                        certs.private_key_path = duplicate_string(optarg);
                        if (certs.private_key_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for certificate");
                                return -1;
                        }
                        break;
                case 0x05: /* intermediate */
                        certs.intermediate_path = duplicate_string(optarg);
                        if (certs.intermediate_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for certificate");
                                return -1;
                        }
                        break;
                case 0x06: /* root */
                        certs.root_path = duplicate_string(optarg);
                        if (certs.root_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for certificate");
                                return -1;
                        }
                        break;
                case 0x07: /* additional_key */
                        certs.additional_key_path = duplicate_string(optarg);
                        if (certs.additional_key_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for certificate");
                                return -1;
                        }
                        break;
                case 0x08: /* no_mutual_auth */
                        tls_config.mutual_authentication = false;
                        break;
                case 0x09: /* ciphersuites */
                        tls_config.ciphersuites = duplicate_string(optarg);
                        if (tls_config.ciphersuites == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for ciphersuites");
                                return -1;
                        }
                        break;
                case 0x0A: /* pre_shared_key */
                        tls_config.psk.enable_psk = true;
                        /* In the optarg, the concatination <id:key> is present. We strip
                         * the key from the identity below. */
                        tls_config.psk.identity = duplicate_string(optarg);
                        if (tls_config.psk.identity == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for PSK key");
                                return -1;
                        }
                        break;
                case 0x0B: /* key_exchange_alg */
                        {
                                enum asl_key_exchange_method kex_algo;
                                if (strcmp(optarg, "secp256") == 0)
                                        kex_algo = ASL_KEX_CLASSIC_SECP256;
                                else if (strcmp(optarg, "secp384") == 0)
                                        kex_algo = ASL_KEX_CLASSIC_SECP384;
                                else if (strcmp(optarg, "secp521") == 0)
                                        kex_algo = ASL_KEX_CLASSIC_SECP521;
                                else if (strcmp(optarg, "x25519") == 0)
                                        kex_algo = ASL_KEX_CLASSIC_X25519;
                                else if (strcmp(optarg, "x448") == 0)
                                        kex_algo = ASL_KEX_CLASSIC_X448;
                                else if (strcmp(optarg, "mlkem512") == 0)
                                        kex_algo = ASL_KEX_PQC_MLKEM512;
                                else if (strcmp(optarg, "mlkem768") == 0)
                                        kex_algo = ASL_KEX_PQC_MLKEM768;
                                else if (strcmp(optarg, "mlkem1024") == 0)
                                        kex_algo = ASL_KEX_PQC_MLKEM1024;
                                else if (strcmp(optarg, "secp256_mlkem512") == 0)
                                        kex_algo = ASL_KEX_HYBRID_SECP256_MLKEM512;
                                else if (strcmp(optarg, "secp384_mlkem768") == 0)
                                        kex_algo = ASL_KEX_HYBRID_SECP384_MLKEM768;
                                else if (strcmp(optarg, "secp256_mlkem768") == 0)
                                        kex_algo = ASL_KEX_HYBRID_SECP256_MLKEM768;
                                else if (strcmp(optarg, "secp521_mlkem1024") == 0)
                                        kex_algo = ASL_KEX_HYBRID_SECP521_MLKEM1024;
                                else if (strcmp(optarg, "secp384_mlkem1024") == 0)
                                        kex_algo = ASL_KEX_HYBRID_SECP384_MLKEM1024;
                                else if (strcmp(optarg, "x25519_mlkem512") == 0)
                                        kex_algo = ASL_KEX_HYBRID_X25519_MLKEM512;
                                else if (strcmp(optarg, "x448_mlkem768") == 0)
                                        kex_algo = ASL_KEX_HYBRID_X448_MLKEM768;
                                else if (strcmp(optarg, "x25519_mlkem768") == 0)
                                        kex_algo = ASL_KEX_HYBRID_X25519_MLKEM768;
                                else
                                {
                                        printf("invalid key exchange algorithm: %s\r\n", optarg);
                                        print_help(argv[0]);
                                        return 1;
                                }
                                tls_config.key_exchange_method = kex_algo;
                                break;
                        }
                case 0x0C: /* pkcs11_module */
                        tls_config.pkcs11.module_path = duplicate_string(optarg);
                        if (tls_config.pkcs11.module_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for PKCS#11 module path");
                                return -1;
                        }
                        break;
                case 0x0D: /* pkcs11_pin */
                        tls_config.pkcs11.module_pin = duplicate_string(optarg);
                        if (tls_config.pkcs11.module_pin == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for PKCS#11 module pin");
                                return -1;
                        }
                        break;
                case 0x0E: /* pkcs11_crypto_all */
                        tls_config.pkcs11.use_for_all = true;
                        break;
                case 0x0F: /* test_num_handshakes */
                        tester_config->handshake_test.iterations = (int) strtol(optarg, NULL, 10);
                        break;
                case 0x10: /* test_handshake_delay */
                        tester_config->handshake_test.delay_ms = (int) strtol(optarg, NULL, 10);
                        break;
                case 0x11: /* test_num_messages */
                        tester_config->message_latency_test.iterations = (int) strtol(optarg, NULL, 10);
                        break;
                case 0x12: /* test_message_delay */
                        tester_config->message_latency_test.delay_us = (int) strtol(optarg, NULL, 10);
                        break;
                case 0x13: /* test_message_size */
                        tester_config->message_latency_test.size = (int) strtol(optarg, NULL, 10);
                        break;
                case 0x14: /* test_output_path */
                        tester_config->output_path = duplicate_string(optarg);
                        if (tester_config->output_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for output path");
                                return -1;
                        }
                        break;
                case 0x15: /* test_no_tls */
                        tester_config->use_tls = false;
                        break;
                case 0x16: /* test_silent */
                        tester_config->silent_test = true;
                        break;
                case 0x17: /* keylog_file */
                        tls_config.keylog_file = duplicate_string(optarg);
                        if (tls_config.keylog_file == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for keylog file path");
                                return -1;
                        }
                        break;
                case 0x18: // management
                        {
                                *mgmt_config_path = duplicate_string(optarg);
                                if (*mgmt_config_path == NULL)
                                {
                                        LOG_ERROR("unable to allocate memory for "
                                                  "management file path");

                                        return -1;
                                }
                                break;
                        }
                case 0x19: /* psk_no_cert_auth */
                        tls_config.psk.enable_cert_auth = false;
                        break;
                case 0x20: /* qkd certificate path */
                        qkd_certs.certificate_path = duplicate_string(optarg);
                        if (qkd_certs.certificate_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for qkd certificate");
                                return -1;
                        }
                        break;
                case 0x21: /* qkd private key path */
                        qkd_certs.private_key_path = duplicate_string(optarg);
                        if (qkd_certs.private_key_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for qkd certificate");
                                return -1;
                        }
                        break;
                case 0x22: /* qkd root certificate path */
                        qkd_certs.root_path = duplicate_string(optarg);
                        if (qkd_certs.root_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for qkd certificate");
                                return -1;
                        }
                        break;
                case 0x23: /* psk_no_kex */
                        tls_config.psk.enable_kex = false;
                        break;
                case 0x24: /* qkd pre-shared key */
                        qkd_config.psk.enable_psk = true;
                        /* In the optarg, the concatination <id:key> is present. We strip
                         * the key from the identity below. */
                        qkd_config.psk.identity = duplicate_string(optarg);
                        if (qkd_config.psk.identity == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for PSK key");
                                return -1;
                        }
                        break;
                case 0x25: /* psk pre-extracted */
                        tls_config.psk.pre_extracted = true;
                        break;
                case 0x26: /* qkd_node */
                        if (parse_ip_address(optarg,
                                             &quest_config->connection_info.hostname,
                                             &quest_config->connection_info.hostport,
                                             &qkd_protocol) != 0)
                        {
                                LOG_ERROR("unable to parse qkd_node IP address");
                                return -1;
                        }
                        break;
                case 0x27: /* qkd_own_sae_id */
                        quest_config->connection_info.own_sae_ID = duplicate_string(optarg);
                        if (quest_config->connection_info.own_sae_ID == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for own QKD SAE ID");
                                return -1;
                        }
                        break;
                case 0x28: /* qkd_remote_sae_id */
                        quest_config->connection_info.remote_sae_ID = duplicate_string(optarg);
                        if (quest_config->connection_info.remote_sae_ID == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for remote QKD SAE ID");
                                return -1;
                        }
                        break;
                case 0x29: /* pkcs11_slot_id */
                        tls_config.pkcs11.slot_id = (int) strtol(optarg, NULL, 10);
                        break;
                case 0x30: /* test_name */
                        tester_config->test_name = duplicate_string(optarg);
                        if (tester_config->test_name == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for test name");
                                return -1;
                        }
                        break;
                case 0x31: /* in_cert */
                        in_certs.certificate_path = duplicate_string(optarg);
                        if (in_certs.certificate_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for in certificate");
                                return -1;
                        }
                        break;
                case 0x32: /* in_key */
                        in_certs.private_key_path = duplicate_string(optarg);
                        if (in_certs.private_key_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for in private key");
                                return -1;
                        }
                        break;
                case 0x33: /* in_intermediate */
                        in_certs.intermediate_path = duplicate_string(optarg);
                        if (in_certs.intermediate_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for in intermediate");
                                return -1;
                        }
                        break;
                case 0x34: /* in_root */
                        in_certs.root_path = duplicate_string(optarg);
                        if (in_certs.root_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for in root");
                                return -1;
                        }
                        break;
                case 0x35: /* in_additional_key */
                        in_certs.additional_key_path = duplicate_string(optarg);
                        if (in_certs.additional_key_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for in additional key");
                                return -1;
                        }
                        break;
                case 0x36: /* in_no_mutual_auth */
                        in_tls_config.mutual_authentication = false;
                        break;
                case 0x37: /* in_ciphersuites */
                        in_tls_config.ciphersuites = duplicate_string(optarg);
                        if (in_tls_config.ciphersuites == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for in ciphersuites");
                                return -1;
                        }
                        break;
                case 0x38: /* in_key_exchange_alg */
                        {
                                enum asl_key_exchange_method kex_algo;
                                if (strcmp(optarg, "secp256") == 0)
                                        kex_algo = ASL_KEX_CLASSIC_SECP256;
                                else if (strcmp(optarg, "secp384") == 0)
                                        kex_algo = ASL_KEX_CLASSIC_SECP384;
                                else if (strcmp(optarg, "secp521") == 0)
                                        kex_algo = ASL_KEX_CLASSIC_SECP521;
                                else if (strcmp(optarg, "x25519") == 0)
                                        kex_algo = ASL_KEX_CLASSIC_X25519;
                                else if (strcmp(optarg, "x448") == 0)
                                        kex_algo = ASL_KEX_CLASSIC_X448;
                                else if (strcmp(optarg, "mlkem512") == 0)
                                        kex_algo = ASL_KEX_PQC_MLKEM512;
                                else if (strcmp(optarg, "mlkem768") == 0)
                                        kex_algo = ASL_KEX_PQC_MLKEM768;
                                else if (strcmp(optarg, "mlkem1024") == 0)
                                        kex_algo = ASL_KEX_PQC_MLKEM1024;
                                else if (strcmp(optarg, "secp256_mlkem512") == 0)
                                        kex_algo = ASL_KEX_HYBRID_SECP256_MLKEM512;
                                else if (strcmp(optarg, "secp384_mlkem768") == 0)
                                        kex_algo = ASL_KEX_HYBRID_SECP384_MLKEM768;
                                else if (strcmp(optarg, "secp256_mlkem768") == 0)
                                        kex_algo = ASL_KEX_HYBRID_SECP256_MLKEM768;
                                else if (strcmp(optarg, "secp521_mlkem1024") == 0)
                                        kex_algo = ASL_KEX_HYBRID_SECP521_MLKEM1024;
                                else if (strcmp(optarg, "secp384_mlkem1024") == 0)
                                        kex_algo = ASL_KEX_HYBRID_SECP384_MLKEM1024;
                                else if (strcmp(optarg, "x25519_mlkem512") == 0)
                                        kex_algo = ASL_KEX_HYBRID_X25519_MLKEM512;
                                else if (strcmp(optarg, "x448_mlkem768") == 0)
                                        kex_algo = ASL_KEX_HYBRID_X448_MLKEM768;
                                else if (strcmp(optarg, "x25519_mlkem768") == 0)
                                        kex_algo = ASL_KEX_HYBRID_X25519_MLKEM768;
                                else
                                {
                                        printf("invalid in key exchange algorithm: %s\r\n", optarg);
                                        print_help(argv[0]);
                                        return 1;
                                }
                                in_tls_config.key_exchange_method = kex_algo;
                                break;
                        }
                case 0x39: /* in_pre_shared_key */
                        in_tls_config.psk.enable_psk = true;
                        /* In the optarg, the concatination <id:key> is present. We strip
                         * the key from the identity below. */
                        in_tls_config.psk.identity = duplicate_string(optarg);
                        if (in_tls_config.psk.identity == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for in PSK key");
                                return -1;
                        }
                        break;
                case 0x3A: /* in_psk_no_cert_auth */
                        in_tls_config.psk.enable_cert_auth = false;
                        break;
                case 0x3B: /* in_psk_no_kex */
                        in_tls_config.psk.enable_kex = false;
                        break;
                case 0x3C: /* in_psk_pre_extracted */
                        in_tls_config.psk.pre_extracted = true;
                        break;
                case 0x49: /* in_pkcs11_module */
                        in_tls_config.pkcs11.module_path = duplicate_string(optarg);
                        if (in_tls_config.pkcs11.module_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for in PKCS#11 module path");
                                return -1;
                        }
                        break;
                case 0x4A: /* in_pkcs11_pin */
                        in_tls_config.pkcs11.module_pin = duplicate_string(optarg);
                        if (in_tls_config.pkcs11.module_pin == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for in PKCS#11 module pin");
                                return -1;
                        }
                        break;
                case 0x4B: /* in_pkcs11_slot_id */
                        in_tls_config.pkcs11.slot_id = (int) strtol(optarg, NULL, 10);
                        break;
                case 0x4C: /* in_pkcs11_crypto_all */
                        in_tls_config.pkcs11.use_for_all = true;
                        break;
                case 0x4D: /* in_keylog_file */
                        in_tls_config.keylog_file = duplicate_string(optarg);
                        if (in_tls_config.keylog_file == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for in keylog file path");
                                return -1;
                        }
                        break;
                case 0x3D: /* out_cert */
                        out_certs.certificate_path = duplicate_string(optarg);
                        if (out_certs.certificate_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for out certificate");
                                return -1;
                        }
                        break;
                case 0x3E: /* out_key */
                        out_certs.private_key_path = duplicate_string(optarg);
                        if (out_certs.private_key_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for out private key");
                                return -1;
                        }
                        break;
                case 0x3F: /* out_intermediate */
                        out_certs.intermediate_path = duplicate_string(optarg);
                        if (out_certs.intermediate_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for out intermediate");
                                return -1;
                        }
                        break;
                case 0x40: /* out_root */
                        out_certs.root_path = duplicate_string(optarg);
                        if (out_certs.root_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for out root");
                                return -1;
                        }
                        break;
                case 0x41: /* out_additional_key */
                        out_certs.additional_key_path = duplicate_string(optarg);
                        if (out_certs.additional_key_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for out additional key");
                                return -1;
                        }
                        break;
                case 0x42: /* out_no_mutual_auth */
                        out_tls_config.mutual_authentication = false;
                        break;
                case 0x43: /* out_ciphersuites */
                        out_tls_config.ciphersuites = duplicate_string(optarg);
                        if (out_tls_config.ciphersuites == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for out ciphersuites");
                                return -1;
                        }
                        break;
                case 0x44: /* out_key_exchange_alg */
                        {
                                enum asl_key_exchange_method kex_algo;
                                if (strcmp(optarg, "secp256") == 0)
                                        kex_algo = ASL_KEX_CLASSIC_SECP256;
                                else if (strcmp(optarg, "secp384") == 0)
                                        kex_algo = ASL_KEX_CLASSIC_SECP384;
                                else if (strcmp(optarg, "secp521") == 0)
                                        kex_algo = ASL_KEX_CLASSIC_SECP521;
                                else if (strcmp(optarg, "x25519") == 0)
                                        kex_algo = ASL_KEX_CLASSIC_X25519;
                                else if (strcmp(optarg, "x448") == 0)
                                        kex_algo = ASL_KEX_CLASSIC_X448;
                                else if (strcmp(optarg, "mlkem512") == 0)
                                        kex_algo = ASL_KEX_PQC_MLKEM512;
                                else if (strcmp(optarg, "mlkem768") == 0)
                                        kex_algo = ASL_KEX_PQC_MLKEM768;
                                else if (strcmp(optarg, "mlkem1024") == 0)
                                        kex_algo = ASL_KEX_PQC_MLKEM1024;
                                else if (strcmp(optarg, "secp256_mlkem512") == 0)
                                        kex_algo = ASL_KEX_HYBRID_SECP256_MLKEM512;
                                else if (strcmp(optarg, "secp384_mlkem768") == 0)
                                        kex_algo = ASL_KEX_HYBRID_SECP384_MLKEM768;
                                else if (strcmp(optarg, "secp256_mlkem768") == 0)
                                        kex_algo = ASL_KEX_HYBRID_SECP256_MLKEM768;
                                else if (strcmp(optarg, "secp521_mlkem1024") == 0)
                                        kex_algo = ASL_KEX_HYBRID_SECP521_MLKEM1024;
                                else if (strcmp(optarg, "secp384_mlkem1024") == 0)
                                        kex_algo = ASL_KEX_HYBRID_SECP384_MLKEM1024;
                                else if (strcmp(optarg, "x25519_mlkem512") == 0)
                                        kex_algo = ASL_KEX_HYBRID_X25519_MLKEM512;
                                else if (strcmp(optarg, "x448_mlkem768") == 0)
                                        kex_algo = ASL_KEX_HYBRID_X448_MLKEM768;
                                else if (strcmp(optarg, "x25519_mlkem768") == 0)
                                        kex_algo = ASL_KEX_HYBRID_X25519_MLKEM768;
                                else
                                {
                                        printf("invalid in key exchange algorithm: %s\r\n", optarg);
                                        print_help(argv[0]);
                                        return 1;
                                }
                                out_tls_config.key_exchange_method = kex_algo;
                                break;
                        }
                case 0x45: /* out_pre_shared_key */
                        out_tls_config.psk.enable_psk = true;
                        /* In the optarg, the concatination <id:key> is present. We strip
                         * the key from the identity below. */
                        out_tls_config.psk.identity = duplicate_string(optarg);
                        if (out_tls_config.psk.identity == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for out PSK key");
                                return -1;
                        }
                        break;
                case 0x46: /* out_psk_no_cert_auth */
                        out_tls_config.psk.enable_cert_auth = false;
                        break;
                case 0x47: /* out_psk_no_kex */
                        out_tls_config.psk.enable_kex = false;
                        break;
                case 0x48: /* out_psk_pre_extracted */
                        out_tls_config.psk.pre_extracted = true;
                        break;
                case 0x4E: /* out_pkcs11_module */
                        out_tls_config.pkcs11.module_path = duplicate_string(optarg);
                        if (out_tls_config.pkcs11.module_path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for out PKCS#11 module path");
                                return -1;
                        }
                        break;
                case 0x4F: /* out_pkcs11_pin */
                        out_tls_config.pkcs11.module_pin = duplicate_string(optarg);
                        if (out_tls_config.pkcs11.module_pin == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for out PKCS#11 module pin");
                                return -1;
                        }
                        break;
                case 0x50: /* out_pkcs11_slot_id */
                        out_tls_config.pkcs11.slot_id = (int) strtol(optarg, NULL, 10);
                        break;
                case 0x51: /* out_pkcs11_crypto_all */
                        out_tls_config.pkcs11.use_for_all = true;
                        break;
                case 0x52: /* out_keylog_file */
                        out_tls_config.keylog_file = duplicate_string(optarg);
                        if (out_tls_config.keylog_file == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for out keylog file path");
                                return -1;
                        }
                        break;
                case 'v': /* verbose */
                        app_config->log_level = LOG_LVL_INFO;
                        break;
                case 'd': /* debug */
                        app_config->log_level = LOG_LVL_DEBUG;
                        break;
                case 'h': /* help */
                        print_help(argv[0]);
                        return 1;
                        break;
                default:
                        print_help(argv[0]);
                        return 1;
                }
        }
        if ((app_config->role == ROLE_MANAGEMENT_CLIENT) && (*mgmt_config_path != NULL))
                return 0;

        if (app_config->role == ROLE_ECHO_SERVER || app_config->role == ROLE_ECHO_SERVER_PROXY)
        {
                if (!certs.certificate_path && !in_certs.certificate_path)
                {
                        LOG_ERROR("certificate file missing");
                        return -1;
                }
                else if (!certs.private_key_path && !in_certs.private_key_path)
                {
                        LOG_ERROR("private key file missing");
                        return -1;
                }
        }
        else if (app_config->role == ROLE_TLS_CLIENT || app_config->role == ROLE_NETWORK_TESTER ||
                 app_config->role == ROLE_NETWORK_TESTER_PROXY)
        {
                if (!certs.root_path && !out_certs.root_path)
                {
                        LOG_ERROR("root certificate file missing");
                        return -1;
                }

                if (!outgoing_ip)
                {
                        LOG_ERROR("outgoing IP address missing");
                        return -1;
                }
        }

        /* Set QKD configuration*/
        if (read_certificates(&qkd_certs) != 0)
        {
                return -1;
        }

        qkd_config.device_certificate_chain.buffer = qkd_certs.chain_buffer;
        qkd_config.device_certificate_chain.size = qkd_certs.chain_buffer_size;
        qkd_config.root_certificate.buffer = qkd_certs.root_buffer;
        qkd_config.root_certificate.size = qkd_certs.root_buffer_size;
        qkd_config.private_key.buffer = qkd_certs.key_buffer;
        qkd_config.private_key.size = qkd_certs.key_buffer_size;

        /* Handle TLS arguements for in and out side */

        char* in_proto = incoming_protocol;
        char* out_proto = outgoing_protocol;

        if (in_proto == NULL)
        {
                if (app_config->role == ROLE_ECHO_SERVER ||
                    app_config->role == ROLE_ECHO_SERVER_PROXY || app_config->role == ROLE_PROXY)
                {
                        in_proto = "tls";
                }
                else
                {
                        in_proto = "tcp";
                }
        }
        if (out_proto == NULL)
        {
                if (app_config->role == ROLE_TLS_CLIENT || app_config->role == ROLE_NETWORK_TESTER ||
                    app_config->role == ROLE_NETWORK_TESTER_PROXY)
                {
                        out_proto = "tls";
                }
                else
                {
                        out_proto = "tcp";
                }
        }

        if ((strncasecmp(in_proto, "tls", 3) == 0) && (strncasecmp(out_proto, "tcp", 3) == 0))
        {
                /* Reverse proxy. Use "normal" TLS arguments for input side. */
                proxy_config->incoming_tls = true;
                proxy_config->outgoing_tls = false;

                if (in_certs.certificate_path == NULL && certs.certificate_path != NULL)
                {
                        in_certs.certificate_path = certs.certificate_path;
                        certs.certificate_path = NULL;
                }
                if (in_certs.private_key_path == NULL && certs.private_key_path != NULL)
                {
                        in_certs.private_key_path = certs.private_key_path;
                        certs.private_key_path = NULL;
                }
                if (in_certs.intermediate_path == NULL && certs.intermediate_path != NULL)
                {
                        in_certs.intermediate_path = certs.intermediate_path;
                        certs.intermediate_path = NULL;
                }
                if (in_certs.root_path == NULL && certs.root_path != NULL)
                {
                        in_certs.root_path = certs.root_path;
                        certs.root_path = NULL;
                }
                if (in_certs.additional_key_path == NULL && certs.additional_key_path != NULL)
                {
                        in_certs.additional_key_path = certs.additional_key_path;
                        certs.additional_key_path = NULL;
                }

                if (in_tls_config.mutual_authentication == true &&
                    tls_config.mutual_authentication == false)
                {
                        in_tls_config.mutual_authentication = false;
                }
                if (in_tls_config.ciphersuites == NULL && tls_config.ciphersuites != NULL)
                {
                        in_tls_config.ciphersuites = tls_config.ciphersuites;
                        tls_config.ciphersuites = NULL;
                }
                if (in_tls_config.key_exchange_method == ASL_KEX_DEFAULT &&
                    tls_config.key_exchange_method != ASL_KEX_DEFAULT)
                {
                        in_tls_config.key_exchange_method = tls_config.key_exchange_method;
                }
                if (in_tls_config.psk.identity == NULL && tls_config.psk.identity != NULL)
                {
                        in_tls_config.psk.identity = tls_config.psk.identity;
                        in_tls_config.psk.enable_psk = true;
                        tls_config.psk.identity = NULL;
                        tls_config.psk.enable_psk = false;
                }
                if (in_tls_config.psk.enable_cert_auth == true &&
                    tls_config.psk.enable_cert_auth == false)
                {
                        in_tls_config.psk.enable_cert_auth = false;
                }
                if (in_tls_config.psk.enable_kex == true && tls_config.psk.enable_kex == false)
                {
                        in_tls_config.psk.enable_kex = false;
                }
                if (in_tls_config.psk.pre_extracted == false && tls_config.psk.pre_extracted == true)
                {
                        in_tls_config.psk.pre_extracted = true;
                }
                if (in_tls_config.pkcs11.module_path == NULL && tls_config.pkcs11.module_path != NULL)
                {
                        in_tls_config.pkcs11.module_path = tls_config.pkcs11.module_path;
                        tls_config.pkcs11.module_path = NULL;
                }
                if (in_tls_config.pkcs11.module_pin == NULL && tls_config.pkcs11.module_pin != NULL)
                {
                        in_tls_config.pkcs11.module_pin = tls_config.pkcs11.module_pin;
                        tls_config.pkcs11.module_pin = NULL;
                }
                if (in_tls_config.pkcs11.slot_id == -1 && tls_config.pkcs11.slot_id != -1)
                {
                        in_tls_config.pkcs11.slot_id = tls_config.pkcs11.slot_id;
                        tls_config.pkcs11.slot_id = -1;
                }
                if (in_tls_config.pkcs11.use_for_all == false && tls_config.pkcs11.use_for_all == true)
                {
                        in_tls_config.pkcs11.use_for_all = true;
                        tls_config.pkcs11.use_for_all = false;
                }
                if (in_tls_config.keylog_file == NULL && tls_config.keylog_file != NULL)
                {
                        in_tls_config.keylog_file = tls_config.keylog_file;
                        tls_config.keylog_file = NULL;
                }

                if (check_qkd_config(quest_config, &qkd_config, &in_tls_config, app_config, qkd_protocol) !=
                    0)
                {
                        return -1;
                }

                if (check_pre_shared_key(&in_tls_config, app_config) != 0)
                {
                        return -1;
                }

                if (read_certificates(&in_certs) != 0)
                {
                        return -1;
                }

                /* Set TLS config */
                in_tls_config.device_certificate_chain.buffer = in_certs.chain_buffer;
                in_tls_config.device_certificate_chain.size = in_certs.chain_buffer_size;
                in_tls_config.private_key.buffer = in_certs.key_buffer;
                in_tls_config.private_key.size = in_certs.key_buffer_size;
                in_tls_config.private_key.additional_key_buffer = in_certs.additional_key_buffer;
                in_tls_config.private_key.additional_key_size = in_certs.additional_key_buffer_size;
                in_tls_config.root_certificate.buffer = in_certs.root_buffer;
                in_tls_config.root_certificate.size = in_certs.root_buffer_size;
        }
        else if ((strncasecmp(in_proto, "tcp", 3) == 0) && (strncasecmp(out_proto, "tls", 3) == 0))
        {
                /* Forward proxy. Use "normal" TLS arguments for output side. */
                proxy_config->incoming_tls = false;
                proxy_config->outgoing_tls = true;

                if (out_certs.certificate_path == NULL && certs.certificate_path != NULL)
                {
                        out_certs.certificate_path = certs.certificate_path;
                        certs.certificate_path = NULL;
                }
                if (out_certs.private_key_path == NULL && certs.private_key_path != NULL)
                {
                        out_certs.private_key_path = certs.private_key_path;
                        certs.private_key_path = NULL;
                }
                if (out_certs.intermediate_path == NULL && certs.intermediate_path != NULL)
                {
                        out_certs.intermediate_path = certs.intermediate_path;
                        certs.intermediate_path = NULL;
                }
                if (out_certs.root_path == NULL && certs.root_path != NULL)
                {
                        out_certs.root_path = certs.root_path;
                        certs.root_path = NULL;
                }
                if (out_certs.additional_key_path == NULL && certs.additional_key_path != NULL)
                {
                        out_certs.additional_key_path = certs.additional_key_path;
                        certs.additional_key_path = NULL;
                }

                if (out_tls_config.mutual_authentication == true &&
                    tls_config.mutual_authentication == false)
                {
                        out_tls_config.mutual_authentication = false;
                }
                if (out_tls_config.ciphersuites == NULL && tls_config.ciphersuites != NULL)
                {
                        out_tls_config.ciphersuites = tls_config.ciphersuites;
                        tls_config.ciphersuites = NULL;
                }
                if (out_tls_config.key_exchange_method == ASL_KEX_DEFAULT &&
                    tls_config.key_exchange_method != ASL_KEX_DEFAULT)
                {
                        out_tls_config.key_exchange_method = tls_config.key_exchange_method;
                }
                if (out_tls_config.psk.identity == NULL && tls_config.psk.identity != NULL)
                {
                        out_tls_config.psk.identity = tls_config.psk.identity;
                        out_tls_config.psk.enable_psk = true;
                        tls_config.psk.identity = NULL;
                        tls_config.psk.enable_psk = false;
                }
                if (out_tls_config.psk.enable_cert_auth == true &&
                    tls_config.psk.enable_cert_auth == false)
                {
                        out_tls_config.psk.enable_cert_auth = false;
                }
                if (out_tls_config.psk.enable_kex == true && tls_config.psk.enable_kex == false)
                {
                        out_tls_config.psk.enable_kex = false;
                }
                if (out_tls_config.psk.pre_extracted == false && tls_config.psk.pre_extracted == true)
                {
                        out_tls_config.psk.pre_extracted = true;
                }
                if (out_tls_config.pkcs11.module_path == NULL && tls_config.pkcs11.module_path != NULL)
                {
                        out_tls_config.pkcs11.module_path = tls_config.pkcs11.module_path;
                        tls_config.pkcs11.module_path = NULL;
                }
                if (out_tls_config.pkcs11.module_pin == NULL && tls_config.pkcs11.module_pin != NULL)
                {
                        out_tls_config.pkcs11.module_pin = tls_config.pkcs11.module_pin;
                        tls_config.pkcs11.module_pin = NULL;
                }
                if (out_tls_config.pkcs11.slot_id == -1 && tls_config.pkcs11.slot_id != -1)
                {
                        out_tls_config.pkcs11.slot_id = tls_config.pkcs11.slot_id;
                        tls_config.pkcs11.slot_id = -1;
                }
                if (out_tls_config.pkcs11.use_for_all == false && tls_config.pkcs11.use_for_all == true)
                {
                        out_tls_config.pkcs11.use_for_all = true;
                        tls_config.pkcs11.use_for_all = false;
                }
                if (out_tls_config.keylog_file == NULL && tls_config.keylog_file != NULL)
                {
                        out_tls_config.keylog_file = tls_config.keylog_file;
                        tls_config.keylog_file = NULL;
                }

                if (check_qkd_config(quest_config, &qkd_config, &out_tls_config, app_config, qkd_protocol) !=
                    0)
                {
                        return -1;
                }

                if (check_pre_shared_key(&out_tls_config, app_config) != 0)
                {
                        return -1;
                }

                if (read_certificates(&out_certs) != 0)
                {
                        return -1;
                }

                /* Set TLS config */
                out_tls_config.device_certificate_chain.buffer = out_certs.chain_buffer;
                out_tls_config.device_certificate_chain.size = out_certs.chain_buffer_size;
                out_tls_config.private_key.buffer = out_certs.key_buffer;
                out_tls_config.private_key.size = out_certs.key_buffer_size;
                out_tls_config.private_key.additional_key_buffer = out_certs.additional_key_buffer;
                out_tls_config.private_key.additional_key_size = out_certs.additional_key_buffer_size;
                out_tls_config.root_certificate.buffer = out_certs.root_buffer;
                out_tls_config.root_certificate.size = out_certs.root_buffer_size;
        }
        else if ((strncasecmp(in_proto, "tls", 3) == 0) && (strncasecmp(out_proto, "tls", 3) == 0))
        {
                bool in_qkd = false;
                bool out_qkd = false;

                /* TLS-TLS proxy */
                proxy_config->incoming_tls = true;
                proxy_config->outgoing_tls = true;

                if ((in_tls_config.psk.identity != NULL) &&
                    (strncmp(in_tls_config.psk.identity, QKD_PSK_IDENTIFIER, QKD_PSK_IDENTIFIER_LEN) ==
                     0) &&
                    (out_tls_config.psk.identity != NULL) &&
                    (strncmp(out_tls_config.psk.identity, QKD_PSK_IDENTIFIER, QKD_PSK_IDENTIFIER_LEN) ==
                     0))
                {
                        LOG_ERROR("QKD PSK cannot be used on both sides of the proxy");
                        return -1;
                }

                if (in_tls_config.psk.identity != NULL)
                {
                        if (strncmp(in_tls_config.psk.identity,
                                    QKD_PSK_IDENTIFIER,
                                    QKD_PSK_IDENTIFIER_LEN) == 0)
                        {
                                if (check_qkd_config(quest_config,
                                                     &qkd_config,
                                                     &in_tls_config,
                                                     app_config,
                                                     qkd_protocol) != 0)
                                {
                                        return -1;
                                }
                        }

                        if (check_pre_shared_key(&in_tls_config, app_config) != 0)
                        {
                                return -1;
                        }

                        in_qkd = app_config->use_qkd;
                }

                if (out_tls_config.psk.identity != NULL)
                {
                        if (strncmp(out_tls_config.psk.identity,
                                    QKD_PSK_IDENTIFIER,
                                    QKD_PSK_IDENTIFIER_LEN) == 0)
                        {
                                if (check_qkd_config(quest_config,
                                                     &qkd_config,
                                                     &out_tls_config,
                                                     app_config,
                                                     qkd_protocol) != 0)
                                {
                                        return -1;
                                }
                        }

                        if (check_pre_shared_key(&out_tls_config, app_config) != 0)
                        {
                                return -1;
                        }

                        out_qkd = app_config->use_qkd;
                }

                app_config->use_qkd = in_qkd || out_qkd;

                if (read_certificates(&in_certs) != 0)
                {
                        return -1;
                }

                /* Set TLS config */
                in_tls_config.device_certificate_chain.buffer = in_certs.chain_buffer;
                in_tls_config.device_certificate_chain.size = in_certs.chain_buffer_size;
                in_tls_config.private_key.buffer = in_certs.key_buffer;
                in_tls_config.private_key.size = in_certs.key_buffer_size;
                in_tls_config.private_key.additional_key_buffer = in_certs.additional_key_buffer;
                in_tls_config.private_key.additional_key_size = in_certs.additional_key_buffer_size;
                in_tls_config.root_certificate.buffer = in_certs.root_buffer;
                in_tls_config.root_certificate.size = in_certs.root_buffer_size;

                if (read_certificates(&out_certs) != 0)
                {
                        return -1;
                }

                /* Set TLS config */
                out_tls_config.device_certificate_chain.buffer = out_certs.chain_buffer;
                out_tls_config.device_certificate_chain.size = out_certs.chain_buffer_size;
                out_tls_config.private_key.buffer = out_certs.key_buffer;
                out_tls_config.private_key.size = out_certs.key_buffer_size;
                out_tls_config.private_key.additional_key_buffer = out_certs.additional_key_buffer;
                out_tls_config.private_key.additional_key_size = out_certs.additional_key_buffer_size;
                out_tls_config.root_certificate.buffer = out_certs.root_buffer;
                out_tls_config.root_certificate.size = out_certs.root_buffer_size;
        }

        /* Store the parsed configuration data in the relevant structures depending on the role */
        if (app_config->role == ROLE_NETWORK_TESTER)
        {
                tester_config->log_level = app_config->log_level;
                tester_config->target_ip = outgoing_ip;
                tester_config->target_port = outgoing_port;
                tester_config->tls_config = out_tls_config;

                if (incoming_ip != NULL)
                {
                        free(incoming_ip);
                }
        }
        else if (app_config->role == ROLE_NETWORK_TESTER_PROXY)
        {
                tester_config->log_level = app_config->log_level;
                tester_config->target_ip = duplicate_string(LOCALHOST_IP);
                tester_config->target_port = incoming_port; /* Must be updated after the proxy started */
                tester_config->use_tls = false;

                proxy_backend_config->log_level = app_config->log_level;

                proxy_config->incoming_ip_address = duplicate_string(LOCALHOST_IP);
                proxy_config->incoming_port = 0; /* 0 selects random available port */
                proxy_config->outgoing_ip_address = outgoing_ip;
                proxy_config->outgoing_port = outgoing_port;
                proxy_config->outgoing_tls = true;
                proxy_config->log_level = app_config->log_level;
                proxy_config->outgoing_tls_config = out_tls_config;

                if (incoming_ip != NULL)
                {
                        free(incoming_ip);
                }
        }
        else if (app_config->role == ROLE_ECHO_SERVER)
        {
                echo_server_config->own_ip_address = incoming_ip;
                echo_server_config->listening_port = incoming_port;
                echo_server_config->log_level = app_config->log_level;
                if (tester_config->use_tls == false)
                {
                        echo_server_config->use_tls = false;
                }
                else
                {
                        if (strncasecmp(in_proto, "tls", 3) == 0)
                        {
                                echo_server_config->use_tls = true;
                        }
                        else
                        {
                                echo_server_config->use_tls = false;
                        }
                }
                echo_server_config->tls_config = in_tls_config;

                if (outgoing_ip != NULL)
                {
                        free(outgoing_ip);
                }
        }
        else if (app_config->role == ROLE_ECHO_SERVER_PROXY)
        {
                echo_server_config->own_ip_address = duplicate_string(LOCALHOST_IP);
                echo_server_config->listening_port = 0; /* 0 selects random available port */
                echo_server_config->log_level = app_config->log_level;
                echo_server_config->use_tls = false;

                proxy_backend_config->log_level = app_config->log_level;

                proxy_config->incoming_ip_address = incoming_ip;
                proxy_config->incoming_port = incoming_port;
                proxy_config->incoming_tls = true;
                proxy_config->outgoing_ip_address = duplicate_string(LOCALHOST_IP);
                proxy_config->outgoing_port = 0; /* Must be updated after the echo server started */
                proxy_config->log_level = app_config->log_level;
                proxy_config->incoming_tls_config = in_tls_config;

                if (outgoing_ip != NULL)
                {
                        free(outgoing_ip);
                }
        }
        else if (app_config->role == ROLE_TLS_CLIENT)
        {
                proxy_backend_config->log_level = app_config->log_level;

                proxy_config->incoming_ip_address = duplicate_string(LOCALHOST_IP);
                proxy_config->incoming_port = 0; /* 0 selects random available port */
                proxy_config->outgoing_ip_address = outgoing_ip;
                proxy_config->outgoing_port = outgoing_port;
                proxy_config->outgoing_tls = true;
                proxy_config->log_level = app_config->log_level;
                proxy_config->outgoing_tls_config = out_tls_config;

                if (incoming_ip != NULL)
                {
                        free(incoming_ip);
                }
        }
        else if (app_config->role == ROLE_PROXY)
        {
                proxy_backend_config->log_level = app_config->log_level;

                proxy_config->incoming_ip_address = incoming_ip;
                proxy_config->incoming_port = incoming_port;
                proxy_config->outgoing_ip_address = outgoing_ip;
                proxy_config->outgoing_port = outgoing_port;
                proxy_config->log_level = app_config->log_level;
                proxy_config->incoming_tls_config = in_tls_config;
                proxy_config->outgoing_tls_config = out_tls_config;
        }

        if (qkd_protocol != NULL)
        {
                free(qkd_protocol);
        }
        if (outgoing_protocol != NULL)
        {
                free(outgoing_protocol);
        }
        if (incoming_protocol != NULL)
        {
                free(incoming_protocol);
        }
        if (in_certs.certificate_path != NULL)
        {
                free((void*) in_certs.certificate_path);
                in_certs.certificate_path = NULL;
        }
        if (in_certs.private_key_path != NULL)
        {
                free((void*) in_certs.private_key_path);
                in_certs.private_key_path = NULL;
        }
        if (in_certs.additional_key_path != NULL)
        {
                free((void*) in_certs.additional_key_path);
                in_certs.additional_key_path = NULL;
        }
        if (in_certs.intermediate_path != NULL)
        {
                free((void*) in_certs.intermediate_path);
                in_certs.intermediate_path = NULL;
        }
        if (in_certs.root_path != NULL)
        {
                free((void*) in_certs.root_path);
                in_certs.root_path = NULL;
        }
        if (out_certs.certificate_path != NULL)
        {
                free((void*) out_certs.certificate_path);
                out_certs.certificate_path = NULL;
        }
        if (out_certs.private_key_path != NULL)
        {
                free((void*) out_certs.private_key_path);
                out_certs.private_key_path = NULL;
        }
        if (out_certs.additional_key_path != NULL)
        {
                free((void*) out_certs.additional_key_path);
                out_certs.additional_key_path = NULL;
        }
        if (out_certs.intermediate_path != NULL)
        {
                free((void*) out_certs.intermediate_path);
                out_certs.intermediate_path = NULL;
        }
        if (out_certs.root_path != NULL)
        {
                free((void*) out_certs.root_path);
                out_certs.root_path = NULL;
        }
        if (certs.certificate_path != NULL)
        {
                free((void*) certs.certificate_path);
                certs.certificate_path = NULL;
        }
        if (certs.private_key_path != NULL)
        {
                free((void*) certs.private_key_path);
                certs.private_key_path = NULL;
        }
        if (certs.additional_key_path != NULL)
        {
                free((void*) certs.additional_key_path);
                certs.additional_key_path = NULL;
        }
        if (certs.intermediate_path != NULL)
        {
                free((void*) certs.intermediate_path);
                certs.intermediate_path = NULL;
        }
        if (certs.root_path != NULL)
        {
                free((void*) certs.root_path);
                certs.root_path = NULL;
        }
        if (qkd_certs.certificate_path != NULL)
        {
                free((void*) qkd_certs.certificate_path);
                qkd_certs.certificate_path = NULL;
        }
        if (qkd_certs.root_path != NULL)
        {
                free((void*) qkd_certs.root_path);
                qkd_certs.root_path = NULL;
        }
        if (qkd_certs.private_key_path != NULL)
        {
                free((void*) qkd_certs.private_key_path);
                qkd_certs.private_key_path = NULL;
        }

        return 0;
}

static int check_qkd_config(quest_configuration* quest_config,
                            asl_endpoint_configuration* qkd_config,
                            asl_endpoint_configuration* tls_config,
                            application_config* app_config,
                            char* qkd_protocol)
{
        /* Check if qkd was selected as psk and TLS is set as protocol */
        if ((tls_config->psk.identity != NULL) &&
            (strncmp(tls_config->psk.identity, QKD_PSK_IDENTIFIER, QKD_PSK_IDENTIFIER_LEN) == 0) &&
            (qkd_protocol != NULL) && (strcmp(qkd_protocol, "tls") == 0))
        {
                /* In this case the qkd_cert, qkd_key and qkd_root options must be set */
                if ((qkd_config->root_certificate.buffer == NULL) ||
                    (qkd_config->private_key.buffer == NULL) ||
                    (qkd_config->device_certificate_chain.buffer == NULL))
                {
                        LOG_ERROR("QKD certificates are mandatory for secure QKD connection");
                        return -1;
                }

                /* In case the connetion to the qkd line shall be secured with a psk */
                if (qkd_config->psk.enable_psk)
                {
                        if (check_pre_shared_key(qkd_config, app_config) != 0)
                                return -1;
                }

                if (tls_config->keylog_file != NULL)
                {
                        /* For debug reasons, we copy the keylog_file from the tls_config */
                        qkd_config->keylog_file = duplicate_string(tls_config->keylog_file);
                        if (qkd_config->keylog_file == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for QKD keylog file path");
                                return -1;
                        }
                }

                /* Initialize the resulting asl_endpoint */
                asl_endpoint* https_endpoint = asl_setup_client_endpoint(qkd_config);
                if (https_endpoint == NULL)
                {
                        LOG_ERROR("unable to setup secure QKD connection endpoint");
                        return -1;
                }

                /* Enable secure connection and set asl_endpoint reference */
                quest_config->security_param.enable_secure_con = true;
                quest_config->security_param.client_endpoint = https_endpoint;
        }
        else /* Otherwise we can clear the qkd_config (not required for unsecure qkd) */
        {
                /* In this case we do not need the secure connection and set
                 * the asl_endpoint reference to NULL */
                quest_config->security_param.enable_secure_con = false;
                quest_config->security_param.client_endpoint = NULL;
        }

        /* As last step, we clean-up the qkd_config */
        if (qkd_config->root_certificate.buffer != NULL)
        {
                free((void*) qkd_config->root_certificate.buffer);
                qkd_config->root_certificate.size = 0;
        }
        if (qkd_config->private_key.buffer != NULL)
        {
                free((void*) qkd_config->private_key.buffer);
                qkd_config->private_key.size = 0;
        }
        if (qkd_config->device_certificate_chain.buffer != NULL)
        {
                free((void*) qkd_config->device_certificate_chain.buffer);
                qkd_config->device_certificate_chain.size = 0;
        }
        if (qkd_config->keylog_file != NULL)
        {
                free((void*) qkd_config->keylog_file);
                qkd_config->keylog_file = NULL;
        }

        return 0;
}

static int check_pre_shared_key(asl_endpoint_configuration* tls_config, application_config* app_config)
{
        /* The provided <id:key> concatination is already stored in the identity variable */
        if (tls_config->psk.identity == NULL)
                return 0;

        /* Check if we want to use the external callback feature of the ASL */
        if (strncmp(tls_config->psk.identity, QKD_PSK_IDENTIFIER, QKD_PSK_IDENTIFIER_LEN) == 0)
        {
                app_config->use_qkd = true;

                tls_config->psk.use_external_callbacks = true;

                tls_config->psk.client_cb = asl_psk_client_callback;
                tls_config->psk.server_cb = asl_psk_server_callback;
        }
        else
        {
                app_config->use_qkd = false;

                /* Check if user passed a file path */
                if (file_exists(tls_config->psk.identity))
                {
                        uint8_t* psk_buffer = NULL;
                        size_t psk_len = 0;

                        if (read_file(tls_config->psk.identity, &psk_buffer, &psk_len) < 0)
                        {
                                LOG_ERROR("failed to read PSK from file");
                                if (psk_buffer != NULL)
                                        free(psk_buffer);
                                return -1;
                        }

                        free((char*) tls_config->psk.identity);
                        tls_config->psk.identity = (char*) psk_buffer;
                }

                /* Strip the key from the <id:key> concatination and store it in its own variable */
                char* key_start = strchr(tls_config->psk.identity, ':');
                if (key_start == NULL)
                {
                        LOG_ERROR("invalid PSK format");
                        return -1;
                }
                *key_start = '\0'; /* Terminate the identity string */
                key_start += 1;    /* Skip the colon */

                tls_config->psk.key = duplicate_string(key_start);
                if (tls_config->psk.key == NULL)
                {
                        LOG_ERROR("unable to allocate memory for PSK master key");
                        return -1;
                }
        }

        return 0;
}

/* Cleanup any structures created during argument parsing */
void arguments_cleanup(application_config* app_config,
                       proxy_backend_config* proxy_backend_config,
                       proxy_config* proxy_config,
                       echo_server_config* echo_server_config,
                       char** management_file_path,
                       network_tester_config* tester_config,
                       quest_configuration* quest_config)
{
        /* Nothing to clean here */
        (void) app_config;
        (void) proxy_backend_config;

        asl_endpoint_configuration* tls_config = NULL;

        if (app_config->role == ROLE_NETWORK_TESTER)
        {
                free(tester_config->target_ip);

                tls_config = &tester_config->tls_config;
        }
        else if (app_config->role == ROLE_NETWORK_TESTER_PROXY)
        {
                free(tester_config->target_ip);
                free(proxy_config->incoming_ip_address);
                free(proxy_config->outgoing_ip_address);

                tls_config = &proxy_config->outgoing_tls_config;
        }

        else if (app_config->role == ROLE_MANAGEMENT_CLIENT)
        {
                free(*management_file_path);

                tls_config = &tester_config->tls_config;
        }
        else if (app_config->role == ROLE_ECHO_SERVER)
        {
                free(echo_server_config->own_ip_address);

                tls_config = &echo_server_config->tls_config;
        }
        else if (app_config->role == ROLE_ECHO_SERVER_PROXY)
        {
                free(echo_server_config->own_ip_address);
                free(proxy_config->incoming_ip_address);
                free(proxy_config->outgoing_ip_address);

                tls_config = &proxy_config->incoming_tls_config;
        }
        else if (app_config->role == ROLE_TLS_CLIENT)
        {
                free(proxy_config->incoming_ip_address);
                free(proxy_config->outgoing_ip_address);

                tls_config = &proxy_config->outgoing_tls_config;
        }
        else if (app_config->role == ROLE_PROXY)
        {
                free(proxy_config->incoming_ip_address);
                free(proxy_config->outgoing_ip_address);

                /* incoming_tls_config is freed below */
                tls_config = &proxy_config->incoming_tls_config;

                /* free outgoing_tls_config here */
                /* Free memory of certificates and private key */
                if (proxy_config->outgoing_tls_config.device_certificate_chain.buffer != NULL)
                {
                        free((void*) proxy_config->outgoing_tls_config.device_certificate_chain.buffer);
                }

                if (proxy_config->outgoing_tls_config.private_key.buffer != NULL)
                {
                        free((void*) proxy_config->outgoing_tls_config.private_key.buffer);
                }

                if (proxy_config->outgoing_tls_config.private_key.additional_key_buffer != NULL)
                {
                        free((void*) proxy_config->outgoing_tls_config.private_key.additional_key_buffer);
                }

                if (proxy_config->outgoing_tls_config.root_certificate.buffer != NULL)
                {
                        free((void*) proxy_config->outgoing_tls_config.root_certificate.buffer);
                }

                if (proxy_config->outgoing_tls_config.ciphersuites != NULL)
                {
                        free((void*) proxy_config->outgoing_tls_config.ciphersuites);
                }

                if (proxy_config->outgoing_tls_config.pkcs11.module_path != NULL)
                {
                        free((void*) proxy_config->outgoing_tls_config.pkcs11.module_path);
                }

                if (proxy_config->outgoing_tls_config.psk.key != NULL)
                {
                        free((void*) proxy_config->outgoing_tls_config.psk.key);
                }

                if (proxy_config->outgoing_tls_config.psk.identity != NULL)
                {
                        free((void*) proxy_config->outgoing_tls_config.psk.identity);
                }

                if (proxy_config->outgoing_tls_config.keylog_file != NULL)
                {
                        free((void*) proxy_config->outgoing_tls_config.keylog_file);
                }
        }

        else
        {
                LOG_ERROR("unsupported role");
                return;
        }

        /* Free memory of the quest configuration */
        if (quest_config != NULL)
        {
                quest_config_deinit(quest_config);
        }

        /* Free memory of certificates and private key */
        if (tls_config->device_certificate_chain.buffer != NULL)
        {
                free((void*) tls_config->device_certificate_chain.buffer);
        }

        if (tls_config->private_key.buffer != NULL)
        {
                free((void*) tls_config->private_key.buffer);
        }

        if (tls_config->private_key.additional_key_buffer != NULL)
        {
                free((void*) tls_config->private_key.additional_key_buffer);
        }

        if (tls_config->root_certificate.buffer != NULL)
        {
                free((void*) tls_config->root_certificate.buffer);
        }

        if (tls_config->ciphersuites != NULL)
        {
                free((void*) tls_config->ciphersuites);
        }

        if (tls_config->pkcs11.module_path != NULL)
        {
                free((void*) tls_config->pkcs11.module_path);
        }

        if (tls_config->psk.key != NULL)
        {
                free((void*) tls_config->psk.key);
        }

        if (tls_config->psk.identity != NULL)
        {
                free((void*) tls_config->psk.identity);
        }

        if (tls_config->keylog_file != NULL)
        {
                free((void*) tls_config->keylog_file);
        }

        if (tester_config->output_path != NULL)
        {
                free((void*) tester_config->output_path);
        }

        if (tester_config->test_name != NULL)
        {
                free((void*) tester_config->test_name);
        }
}

static void print_help(char const* name)
{
        /* clang-format off */
        printf("Usage: %s ROLE [OPTIONS]\r\n", name);
        printf("Roles:\r\n");
        printf("  reverse_proxy                  TLS reverse proxy (use \"--incoming\" and \"--outgoing\" for connection configuration)\r\n");
        printf("  forward_proxy                  TLS forward proxy (use \"--incoming\" and \"--outgoing\" for connection configuration)\r\n");
        printf("  echo_server                    TLS echo server (use \"--incoming\" for connection configuration)\r\n");
        printf("  echo_server_proxy              TLS echo server via reverse proxy (use \"--incoming\" for connection configuration)\r\n");
        printf("  tls_client                     TLS stdin client (use \"--outgoing\" for connection configuration)\r\n");
        printf("  network_tester                 TLS network tester (use \"--outgoing\" for connection configuration)\r\n");
        printf("  network_tester_proxy           TLS network tester via forward proxy (use \"--outgoing\" for connection configuration)\r\n");
        printf("  management_client              Management Client (use \"--mgmt_path to provide config file path)\r\n");

        printf("\nConnection configuration:\r\n");
        printf("  --incoming <ip:>port           Configuration of the incoming TCP/TLS connection\r\n");
        printf("  --outgoing ip:port             Configuration of the outgoing TCP/TLS connection\r\n");

        printf("\nCertificate/Key configuration:\r\n");
        printf("  --cert file_path               Path to the certificate file\r\n");
        printf("  --key file_path                Path to the private key file\r\n");
        printf("  --intermediate file_path       Path to an intermediate certificate file\r\n");
        printf("  --root file_path               Path to the root certificate file\r\n");
        printf("  --additional_key file_path     Path to an additional private key file (hybrid certificate)\r\n");

        printf("\nSecurity configuration:\r\n");
        printf("  --no_mutual_auth               Disable mutual authentication (default enabled)\r\n");
        printf("  --ciphersuites suites          Use given TLS1.3 ciphersuites, separated by \":\". For clients, the first one is selected\r\n");
        printf("                                    for the connection. Default is: \"TLS13-AES256-GCM-SHA384:TLS13-SHA384-SHA384\"\r\n");
        printf("  --key_exchange_alg algorithm   Key exchange algorithm: (default: \"secp384_mlkem768\")\r\n");
        printf("                                    Classic: \"secp256\", \"secp384\", \"secp521\", \"x25519\", \"x448\"\r\n");
        printf("                                    PQC: \"mlkem512\", \"mlkem768\", \"mlkem1024\"\r\n");
        printf("                                    Hybrid: \"secp256_mlkem512\", \"secp384_mlkem768\", \"secp256_mlkem768\"\r\n");
        printf("                                            \"secp521_mlkem1024\", \"secp384_mlkem1024\", \"x25519_mlkem512\"\r\n");
        printf("                                            \"x448_mlkem768\", \"x25519_mlkem768\"\r\n");

        printf("\nPre-shared keys:\r\n");
        printf("  --pre_shared_key id:key        Pre-shared key and identity to use. The identity is sent from client to server during\r\n");
        printf("                                    the handshake. The key has to be Base64 encoded.\r\n");
        printf("  --psk_no_kex                   Disable ephemeral key exchange in addition to the PSK shared secret\r\n");
        printf("  --psk_no_cert_auth             Disable certificates in addition to the PSK for peer authentication\r\n");
        printf("  --psk_pre_extracted            HKDF-Extract operation is already performed, only the Expand part is necessary\r\n");

        printf("\nQKD:\r\n");
        printf("  When using QKD in the TLS applications, you have to specify this in the --pre_shared_key parameter via:.\r\n");
        printf("      --pre_shared_key \"%s\"         Use a REST request to the QKD key magament system via ETSQ QKD 014 API.\r\n", QKD_PSK_IDENTIFIER);
        printf("                                          To use TLS for this conneciton, you have to provide \"tls://\" in front of the\r\n");
        printf("                                          qkd_node argument below. Otherwise TCP is used. In this mode, the qkd_xxx arguments\r\n");
        printf("                                          below must be set.\r\n\n");
        printf("  --qkd_node ip:port             Endpoint of the QKD Node from where the keys are requested.\r\n");
        printf("  --qkd_own_sae_id id            Our own SAE ID within the QKD system.\r\n");
        printf("  --qkd_remote_sae_id id         SAE ID of the remote peer within the QKD system (only needed on the client-side).\r\n");
        printf("  --qkd_cert file_path           Path to the certificate file used for the HTTPS connection to the QKD server\r\n");
        printf("  --qkd_root file_path           Path to the root certificate file used for the HTTPS connection to the QKD server\r\n");
        printf("  --qkd_key file_path            Path to the private key file used for the HTTPS connection to the QKD server\r\n");
        printf("  --qkd_psk id:key               Pre-shared key and identity to use for the HTTPS connection to the QKD server\r\n");
        printf("                                    The key has to be Base64 encoded.\r\n");

        printf("\nPKCS#11:\r\n");
        printf("  When using a PKCS#11 token for key/cert storage, you have to supply the PKCS#11 labels using the arguments\n");
        printf("  \"--key\",\"--additionalKey\", and \"--cert\", prepending the string \"%s\" followed by the label.\r\n", PKCS11_LABEL_IDENTIFIER);
        printf("  As an alternative, the file provided by \"--key\", \"--additionalKey\" or \"--cert\" may also contain the key label with\r\n");
        printf("  the same identifier before it. In this case, the label must be the first line of the file.\r\n\n");
        printf("  To use a pre-shared key on a PKCS#11 token, the \"--pre_shared_key\" arguement is used: instead of a Base64\r\n");
        printf("  encoded key, the label \"%.*s\" has to be specified. In this case, the given PSK identity is used as\r\n", PKCS11_LABEL_IDENTIFIER_LEN - 1,
                                                                                                                             PKCS11_LABEL_IDENTIFIER);
        printf("  the PKCS#11 label of the pre-shared key on the token.\r\n\n");
        printf("  --pkcs11_module file_path      Path to the PKCS#11 token middleware\r\n");
        printf("  --pkcs11_pin pin               PIN for the token (default empty)\r\n");
        printf("  --pkcs11_slot_id id            Slot ID of the PKCS#11 module to use (default 0)\r\n");
        printf("  --pkcs11_crypto_all            Use the PKCS#11 token for all supported crypto operations (default disabled)\r\n");

        printf("\nNetwork tester configuration:\r\n");
        printf("  --test_num_handshakes num      Number of handshakes to perform in the test (default 1)\r\n");
        printf("  --test_handshake_delay num_ms  Delay between handshakes in milliseconds (default 0)\r\n");
        printf("  --test_num_messages num        Number of echo messages to send per handshake iteration (default 0)\r\n");
        printf("  --test_message_delay num_us    Delay between messages in microseconds (default 0)\r\n");
        printf("  --test_message_size num        Size of the echo message in bytes (default 1)\r\n");
        printf("  --test_output_path path        Path to the output file (filename will be appended)\r\n");
        printf("  --test_name name               Name of the test (used in output file names)\r\n");
        printf("  --test_no_tls                  Disable TLS for test (plain TCP; default disabled)\r\n");
        printf("  --test_silent                  Disable progress printing\r\n");

        printf("\nManagement:\r\n");
        printf("  --mgmt_path                    Path to management config\r\n");

        printf("\nGeneral:\r\n");
        printf("  --keylog_file file_path        Path to the keylog file for Wireshark\r\n");
        printf("  --verbose                      Enable verbose output\r\n");
        printf("  --debug                        Enable debug output\r\n");
        printf("  --help                         Display this help and exit\r\n");
        /* clang-format on */
}
