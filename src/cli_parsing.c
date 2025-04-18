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
        {"psk_no_dhe", no_argument, 0, 0x23},
        {"psk_pre_extracted", no_argument, 0, 0x25},

        {"qkd_cert", required_argument, 0, 0x20},
        {"qkd_key", required_argument, 0, 0x21},
        {"qkd_root", required_argument, 0, 0x22},
        {"qkd_psk", required_argument, 0, 0x24},

        {"pkcs11_module", required_argument, 0, 0x0C},
        {"pkcs11_pin", required_argument, 0, 0x0D},
        {"pkcs11_crypto_all", no_argument, 0, 0x0E},

        {"test_num_handshakes", required_argument, 0, 0x0F},
        {"test_handshake_delay", required_argument, 0, 0x10},
        {"test_num_messages", required_argument, 0, 0x11},
        {"test_message_delay", required_argument, 0, 0x12},
        {"test_message_size", required_argument, 0, 0x13},
        {"test_output_path", required_argument, 0, 0x14},
        {"test_no_tls", no_argument, 0, 0x15},
        {"test_silent", no_argument, 0, 0x16},

        {"keylog_file", required_argument, 0, 0x17},

        {"mgmt_path", required_argument, 0, 0x18},

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
                            application_config* app_config);
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
        char* outgoing_ip = NULL;
        uint16_t outgoing_port = 0;

        certificates certs = get_empty_certificates();
        asl_endpoint_configuration tls_config = asl_default_endpoint_config();

        /* TLS config for HTTPS connection to the QKD line */
        certificates qkd_certs = get_empty_certificates();
        asl_endpoint_configuration qkd_config = asl_default_endpoint_config();

        /* Application config */
        app_config->role = NOT_SET;
        app_config->log_level = LOG_LVL_WARN;

        /* Parse role */
        if (strcmp(argv[1], "reverse_proxy") == 0)
        {
                app_config->role = ROLE_REVERSE_PROXY;
        }
        else if (strcmp(argv[1], "forward_proxy") == 0)
        {
                app_config->role = ROLE_FORWARD_PROXY;
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
                        if (parse_ip_address(optarg, &incoming_ip, &incoming_port) != 0)
                        {
                                LOG_ERROR("unable to parse incoming IP address");
                                return -1;
                        }
                        break;
                case 0x02: /* outgoing */
                        if (parse_ip_address(optarg, &outgoing_ip, &outgoing_port) != 0)
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
                case 0x23: /* psk disable (EC)DHE */
                        tls_config.psk.enable_dhe_psk = false;
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

        if (app_config->role == ROLE_REVERSE_PROXY || app_config->role == ROLE_ECHO_SERVER)
        {
                if (!certs.certificate_path)
                {
                        LOG_ERROR("certificate file missing");
                        return -1;
                }
                else if (!certs.private_key_path)
                {
                        LOG_ERROR("private key file missing");
                        return -1;
                }
        }
        else if (app_config->role == ROLE_FORWARD_PROXY || app_config->role == ROLE_TLS_CLIENT)
        {
                if (!certs.root_path)
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

        qkd_config.device_certificate_chain.buffer = qkd_certs.chain_buffer;
        qkd_config.device_certificate_chain.size = qkd_certs.chain_buffer_size;
        qkd_config.root_certificate.buffer = qkd_certs.root_buffer;
        qkd_config.root_certificate.size = qkd_certs.root_buffer_size;
        qkd_config.private_key.buffer = qkd_certs.key_buffer;
        qkd_config.private_key.size = qkd_certs.key_buffer_size;

        if (check_qkd_config(quest_config, &qkd_config, &tls_config, app_config) != 0)
        {
                return -1;
        }

        if (read_certificates(&certs) != 0)
        {
                return -1;
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

        if (check_pre_shared_key(&tls_config, app_config) != 0)
        {
                return -1;
        }

        /* Set TLS config */
        tls_config.device_certificate_chain.buffer = certs.chain_buffer;
        tls_config.device_certificate_chain.size = certs.chain_buffer_size;
        tls_config.private_key.buffer = certs.key_buffer;
        tls_config.private_key.size = certs.key_buffer_size;
        tls_config.private_key.additional_key_buffer = certs.additional_key_buffer;
        tls_config.private_key.additional_key_size = certs.additional_key_buffer_size;
        tls_config.root_certificate.buffer = certs.root_buffer;
        tls_config.root_certificate.size = certs.root_buffer_size;

        /* Store the parsed configuration data in the relevant structures depending on the role */
        if (app_config->role == ROLE_NETWORK_TESTER)
        {
                tester_config->log_level = app_config->log_level;
                tester_config->target_ip = outgoing_ip;
                tester_config->target_port = outgoing_port;
                tester_config->tls_config = tls_config;

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

                proxy_config->own_ip_address = duplicate_string(LOCALHOST_IP);
                proxy_config->listening_port = 0; /* 0 selects random available port */
                proxy_config->target_ip_address = outgoing_ip;
                proxy_config->target_port = outgoing_port;
                proxy_config->log_level = app_config->log_level;
                proxy_config->tls_config = tls_config;

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
                echo_server_config->use_tls = tester_config->use_tls;
                echo_server_config->tls_config = tls_config;

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

                proxy_config->own_ip_address = incoming_ip;
                proxy_config->listening_port = incoming_port;
                proxy_config->target_ip_address = duplicate_string(LOCALHOST_IP);
                proxy_config->target_port = 0; /* Must be updated after the echo server started */
                proxy_config->log_level = app_config->log_level;
                proxy_config->tls_config = tls_config;

                if (outgoing_ip != NULL)
                {
                        free(outgoing_ip);
                }
        }
        else if (app_config->role == ROLE_TLS_CLIENT)
        {
                proxy_backend_config->log_level = app_config->log_level;

                proxy_config->own_ip_address = duplicate_string(LOCALHOST_IP);
                proxy_config->listening_port = 0; /* 0 selects random available port */
                proxy_config->target_ip_address = outgoing_ip;
                proxy_config->target_port = outgoing_port;
                proxy_config->log_level = app_config->log_level;
                proxy_config->tls_config = tls_config;

                if (incoming_ip != NULL)
                {
                        free(incoming_ip);
                }
        }
        else if ((app_config->role == ROLE_REVERSE_PROXY) || (app_config->role == ROLE_FORWARD_PROXY))
        {
                proxy_backend_config->log_level = app_config->log_level;

                proxy_config->own_ip_address = incoming_ip;
                proxy_config->listening_port = incoming_port;
                proxy_config->target_ip_address = outgoing_ip;
                proxy_config->target_port = outgoing_port;
                proxy_config->log_level = app_config->log_level;
                proxy_config->tls_config = tls_config;
        }

        return 0;
}

static int check_qkd_config(quest_configuration* quest_config,
                            asl_endpoint_configuration* qkd_config,
                            asl_endpoint_configuration* tls_config,
                            application_config* app_config)
{
        /* if these roles are set, we are on the server side of the tls communicaton and need to
         * modify the hostname and sae_ID of the quest_configuration to address the correct QKD
           endpoint */
        if ((app_config->role) == ROLE_ECHO_SERVER || (app_config->role == ROLE_REVERSE_PROXY))
        {
                quest_config->connection_info.hostname = "im-lfd-qkd-alice.othr.de";
                quest_config->connection_info.host_sae_ID = "alice_sae_etsi_1";
        }

        /* Check if qkd:secure was selected as qkd usage */
        if (tls_config->psk.identity != NULL && strncmp(tls_config->psk.identity,
                                                        SECURE_QKD_PSK_IDENTIFIER,
                                                        SECURE_QKD_PSK_IDENTIFIER_LEN) == 0)
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
                }

                /* Initialize the resulting asl_endpoint */
                asl_endpoint* https_endpoint = asl_setup_client_endpoint(qkd_config);

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
        if ((strncmp(tls_config->psk.identity, QKD_PSK_IDENTIFIER, QKD_PSK_IDENTIFIER_LEN) == 0) ||
            (strncmp(tls_config->psk.identity, SECURE_QKD_PSK_IDENTIFIER, SECURE_QKD_PSK_IDENTIFIER_LEN) ==
             0))
        {
                app_config->use_qkd = true;

                /* Strip the ":secure" in case of SECURE_QKD_PSK_IDENTIFIER */
                char* key_start = strchr(tls_config->psk.identity, ':');
                if (key_start != NULL)
                        *key_start = '\0'; /* Terminate the identity string */

                tls_config->psk.use_external_callbacks = true;

                tls_config->psk.client_cb = asl_psk_client_callback;
                tls_config->psk.server_cb = asl_psk_server_callback;
        }
        else
        {
                app_config->use_qkd = false;

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

        /* ToDo: Add ability to read PSK from a file here... */

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
                free(proxy_config->own_ip_address);
                free(proxy_config->target_ip_address);

                tls_config = &proxy_config->tls_config;
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
                free(proxy_config->own_ip_address);
                free(proxy_config->target_ip_address);

                tls_config = &proxy_config->tls_config;
        }
        else if (app_config->role == ROLE_TLS_CLIENT)
        {
                free(proxy_config->own_ip_address);
                free(proxy_config->target_ip_address);

                tls_config = &proxy_config->tls_config;
        }
        else if (app_config->role == ROLE_REVERSE_PROXY || app_config->role == ROLE_FORWARD_PROXY)
        {
                free(proxy_config->own_ip_address);
                free(proxy_config->target_ip_address);

                tls_config = &proxy_config->tls_config;
        }
        else
        {
                LOG_ERROR("unsupported role");
                return;
        }

        /* Free memory of the quest configuration */
        if (quest_config != NULL)
        {
                quest_deinit(quest_config);
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
        printf("  --psk_no_dhe                   Disable (EC)DHE key generation in addition to the PSK shared secret\r\n");
        printf("  --psk_no_cert_auth             Disable certificates in addition to the PSK for peer authentication\r\n");
        printf("  --psk_pre_extracted            HKDF-Extract operation is already performed, only the Expand part is necessary\r\n");

        printf("\nQKD:\r\n");
        printf("  When using QKD in the TLS applications, you have to specify this in the --pre_shared_key parameter.\r\n");
        printf("  In that case, two modes are possible:\r\n");
        printf("      --pre_shared_key \"%s\"         Use a HTTP request to the QKD key magament system.\r\n", QKD_PSK_IDENTIFIER);
        printf("      --pre_shared_key \"%s\"  Use a secured HTPPS request to the QKD key management system.\r\n", SECURE_QKD_PSK_IDENTIFIER);
        printf("                                          In this mode, the qkd_xxx arguments below must be set.\r\n\n");
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
        printf("  --pkcs11_crypto_all            Use the PKCS#11 token for all supported crypto operations (default disabled)\r\n");

        printf("\nNetwork tester configuration:\r\n");
        printf("  --test_num_handshakes num      Number of handshakes to perform in the test (default 1)\r\n");
        printf("  --test_handshake_delay num_ms  Delay between handshakes in milliseconds (default 0)\r\n");
        printf("  --test_num_messages num        Number of echo messages to send per handshake iteration (default 0)\r\n");
        printf("  --test_message_delay num_us    Delay between messages in microseconds (default 0)\r\n");
        printf("  --test_message_size num        Size of the echo message in bytes (default 1)\r\n");
        printf("  --test_output_path path        Path to the output file (filename will be appended)\r\n");
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
