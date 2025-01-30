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
        {"integrity_only_cipher", no_argument, 0, 0x09},
        {"key_exchange_alg", required_argument, 0, 0x0B},
        {"pre_shared_key", required_argument, 0, 0x0A},

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
extern unsigned int asl_psk_server_callback(char* key, const char* identity, void* ctx);

static int check_pre_shared_key(asl_endpoint_configuration* tls_config);
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
                        certs.certificate_path = optarg;
                        break;
                case 0x04: /* key */
                        certs.private_key_path = optarg;
                        break;
                case 0x05: /* intermediate */
                        certs.intermediate_path = optarg;
                        break;
                case 0x06: /* root */
                        certs.root_path = optarg;
                        break;
                case 0x07: /* additional_key */
                        certs.additional_key_path = optarg;
                        break;
                case 0x08: /* no_mutual_auth */
                        tls_config.mutual_authentication = false;
                        break;
                case 0x09: /* integrity_only_cipher */
                        tls_config.no_encryption = true;
                        break;
                case 0x0A: /* pre_shared_key */
                        tls_config.psk.enable_psk = true;
                        tls_config.psk.master_key = duplicate_string(optarg);
                        if (tls_config.psk.master_key == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for PSK master key");
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

        if (read_certificates(&certs) != 0)
        {
                return -1;
        }

        if (check_pre_shared_key(&tls_config) != 0)
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
                proxy_config->log_level = LOG_LVL_WARN;
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

static int check_pre_shared_key(asl_endpoint_configuration* tls_config)
{
        if (tls_config->psk.master_key == NULL)
                return 0;

        /* Check if we want to use the external callback feature of the ASL */
        if (strncmp(tls_config->psk.master_key, EXTERNAL_PSK_IDENTIFIER, EXTERNAL_PSK_IDENTIFIER_LEN) ==
            0)
        {
                tls_config->psk.use_external_callbacks = true;

                /* This is temporary, only for testing now... */
                tls_config->psk.callback_ctx = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

                tls_config->psk.psk_client_cb = asl_psk_client_callback;
                tls_config->psk.psk_server_cb = asl_psk_server_callback;

                free((void*) tls_config->psk.master_key);
                tls_config->psk.master_key = NULL;
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
                       network_tester_config* tester_config)
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

        if (tls_config->pkcs11.module_path != NULL)
        {
                free((void*) tls_config->pkcs11.module_path);
        }

        if (tls_config->psk.master_key != NULL)
        {
                free((void*) tls_config->psk.master_key);
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
        printf("  --integrity_only_cipher        Use an integrity-only cipher without encryption (default disabled)\r\n");
        printf("  --key_exchange_alg algorithm   Key exchange algorithm: (default: \"secp384_mlkem768\")\r\n");
        printf("                                    Classic: \"secp256\", \"secp384\", \"secp521\", \"x25519\", \"x448\"\r\n");
        printf("                                    PQC: \"mlkem512\", \"mlkem768\", \"mlkem1024\"\r\n");
        printf("                                    Hybrid: \"secp256_mlkem512\", \"secp384_mlkem768\", \"secp256_mlkem768\"\r\n");
        printf("                                            \"secp521_mlkem1024\", \"secp384_mlkem1024\", \"x25519_mlkem512\"\r\n");
        printf("                                            \"x448_mlkem768\", \"x25519_mlkem768\"\r\n");
        printf("  --pre_shared_key key           Pre-shared key to use (Base64 encoded)\r\n");

        printf("\nPKCS#11:\r\n");
        printf("  When using a PKCS#11 token for key/cert storage, you have to supply the PKCS#11 labels using the arguments\n");
        printf("  \"--key\",\"--additionalKey\", and \"--cert\", prepending the string \"%s\" followed by the label.\r\n", PKCS11_LABEL_IDENTIFIER);
        printf("  As an alternative, the file provided by \"--key\", \"--additionalKey\" or \"--cert\" may also contain the key label with\r\n");
        printf("  the same identifier before it. In this case, the label must be the first line of the file.\r\n");
        printf("  To use a pre-shared master key on a PKCS#11 token, you have to provide the label of the key via the \"--pre_shared_key\"\r\n");
        printf("  argument, prepending the string \"%s\".\r\n", PKCS11_LABEL_IDENTIFIER);
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
