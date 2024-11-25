#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <ctype.h>

#include "logging.h"
#include "networking.h"

#include "cli_parsing.h"

LOG_MODULE_CREATE(cli_parsing);

typedef struct certificates
{
        char const *certificate_path;
        char const *private_key_path;
        char const *additional_key_path;
        char const *intermediate_path;
        char const *root_path;

        uint8_t *chain_buffer; /* Entity and intermediate certificates */
        size_t chain_buffer_size;

        uint8_t *key_buffer;
        size_t key_buffer_size;

        uint8_t *additional_key_buffer;
        size_t additional_key_buffer_size;

        uint8_t *root_buffer;
        size_t root_buffer_size;
} certificates;

static const struct option cli_options[] =
    {
        {"incoming", required_argument, 0, 0x01},
        {"outgoing", required_argument, 0, 0x02},

        {"cert", required_argument, 0, 0x03},
        {"key", required_argument, 0, 0x04},
        {"intermediate", required_argument, 0, 0x05},
        {"root", required_argument, 0, 0x06},
        {"additional_key", required_argument, 0, 0x07},

        {"no_mutual_auth", no_argument, 0, 0x08},
        {"use_null_cipher", no_argument, 0, 0x09},
        {"hybrid_signature", required_argument, 0, 0x0A},
        {"key_exchange_alg", required_argument, 0, 0x0B},

        {"p11_long_term_module", required_argument, 0, 0x0C},
        {"p11_long_term_pin", required_argument, 0, 0x0D},
        {"p11_ephemeral_module", required_argument, 0, 0x0E},

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

        {NULL, 0, NULL, 0}};

static void set_defaults(application_config *app_config, certificates *certs);
static int read_certificates(certificates *certs, enum application_role role);
static void print_help(char const *name);
static int parse_ip_address(char *input, char **ip, uint16_t *port);
static int readFile(const char *filePath, uint8_t **buffer, size_t bufferSize);

/* Parse the provided argv array and store the information in the provided config variables.
 *
 * Returns 0 on success, +1 in case the help was printed and  -1 on failure (error is printed on console).
 */
int parse_cli_arguments(application_config *app_config, proxy_backend_config *proxy_backend_config,
                        proxy_config *proxy_config, echo_server_config *echo_server_config,
                        network_tester_config *tester_config, char **mgmt_config_path, size_t argc, char **argv)
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

        char *incoming_ip = NULL;
        uint16_t incoming_port = 0;
        char *outgoing_ip = NULL;
        uint16_t outgoing_port = 0;

        certificates certs = {0};
        asl_endpoint_configuration tls_config = asl_default_endpoint_config();

        /* Set default values */
        set_defaults(app_config, &certs);

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
                case 0x09: /* use_null_cipher */
                        tls_config.no_encryption = true;
                        break;
                case 0x0A: /* hybrid_signature */
                {
                        enum asl_hybrid_signature_mode mode;
                        if (strcmp(optarg, "both") == 0)
                                mode = ASL_HYBRID_SIGNATURE_MODE_BOTH;
                        else if (strcmp(optarg, "native") == 0)
                                mode = ASL_HYBRID_SIGNATURE_MODE_NATIVE;
                        else if (strcmp(optarg, "alternative") == 0)
                                mode = ASL_HYBRID_SIGNATURE_MODE_ALTERNATIVE;
                        else
                        {
                                printf("invalid hybrid signature mode: %s\r\n", optarg);
                                print_help(argv[0]);
                                return 1;
                        }
                        tls_config.hybrid_signature_mode = mode;
                        break;
                }
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
                case 0x0C: /* p11_long_term_module */
                        tls_config.pkcs11.long_term_crypto_module.path = duplicate_string(optarg);
                        if (tls_config.pkcs11.long_term_crypto_module.path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for PKCS#11 long-termin crypto module path");
                                return -1;
                        }
                        break;
                case 0x0D: /* p11_long_term_pin */
                        tls_config.pkcs11.long_term_crypto_module.pin = duplicate_string(optarg);
                        if (tls_config.pkcs11.long_term_crypto_module.pin == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for PKCS#11 long-term crypto module pin");
                                return -1;
                        }
                        break;
                case 0x0E: /* p11_ephemeral_module */
                        tls_config.pkcs11.ephemeral_crypto_module.path = duplicate_string(optarg);
                        if (tls_config.pkcs11.ephemeral_crypto_module.path == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for PKCS#11 ephemeral crypto module path");
                                return -1;
                        }
                        break;
                case 0x0F: /* test_num_handshakes */
                        tester_config->handshake_test.iterations = (int)strtol(optarg, NULL, 10);
                        break;
                case 0x10: /* test_handshake_delay */
                        tester_config->handshake_test.delay_ms = (int)strtol(optarg, NULL, 10);
                        break;
                case 0x11: /* test_num_messages */
                        tester_config->message_latency_test.iterations = (int)strtol(optarg, NULL, 10);
                        break;
                case 0x12: /* test_message_delay */
                        tester_config->message_latency_test.delay_us = (int)strtol(optarg, NULL, 10);
                        break;
                case 0x13: /* test_message_size */
                        tester_config->message_latency_test.size = (int)strtol(optarg, NULL, 10);
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
                                LOG_ERROR("unable to allocate memory for management file path");

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
        if ((app_config->role == ROLE_MANAGEMENT_CLIENT) &&
            (*mgmt_config_path != NULL))
                return 0;

        /* Read certificates */
        if (read_certificates(&certs, app_config->role) != 0)
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
        else if ((app_config->role == ROLE_REVERSE_PROXY) ||
                 (app_config->role == ROLE_FORWARD_PROXY))
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

/* Cleanup any structures created during argument parsing */
void arguments_cleanup(application_config *app_config, proxy_backend_config *proxy_backend_config,
                       proxy_config *proxy_config, echo_server_config *echo_server_config, char **management_file_path,
                       network_tester_config *tester_config)
{
        /* Nothing to clean here */
        (void)app_config;
        (void)proxy_backend_config;

        asl_endpoint_configuration *tls_config = NULL;

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
                free((void *)tls_config->device_certificate_chain.buffer);
        }

        if (tls_config->private_key.buffer != NULL)
        {
                free((void *)tls_config->private_key.buffer);
        }

        if (tls_config->private_key.additional_key_buffer != NULL)
        {
                free((void *)tls_config->private_key.additional_key_buffer);
        }

        if (tls_config->root_certificate.buffer != NULL)
        {
                free((void *)tls_config->root_certificate.buffer);
        }

        if (tls_config->pkcs11.long_term_crypto_module.path != NULL)
        {
                free((void *)tls_config->pkcs11.long_term_crypto_module.path);
        }

        if (tls_config->pkcs11.ephemeral_crypto_module.path != NULL)
        {
                free((void *)tls_config->pkcs11.ephemeral_crypto_module.path);
        }

        if (tls_config->keylog_file != NULL)
        {
                free((void *)tls_config->keylog_file);
        }
}

/* Helper method to dynamically duplicate a string */
char *duplicate_string(char const *source)
{
        if (source == NULL)
                return NULL;

        char *dest = (char *)malloc(strlen(source) + 1);
        if (dest == NULL)
        {
                LOG_ERROR("unable to allocate memory for string duplication");
                return NULL;
        }
        strcpy(dest, source);

        return dest;
}

static void set_defaults(application_config *app_config, certificates *certs)
{
        /* Certificates */
        certs->certificate_path = NULL;
        certs->private_key_path = NULL;
        certs->additional_key_path = NULL;
        certs->intermediate_path = NULL;
        certs->root_path = NULL;
        certs->chain_buffer = NULL;
        certs->chain_buffer_size = 0;
        certs->key_buffer = NULL;
        certs->key_buffer_size = 0;
        certs->additional_key_buffer = NULL;
        certs->additional_key_buffer_size = 0;
        certs->root_buffer = NULL;
        certs->root_buffer_size = 0;

        /* Application config */
        app_config->role = NOT_SET;
        app_config->log_level = LOG_LVL_WARN;
}

static void print_help(char const *name)
{
        printf("Usage: %s ROLE [OPTIONS]\r\n", name);
        printf("Roles:\r\n");
        printf("  reverse_proxy                      TLS reverse proxy (use \"--incoming\" and \"--outgoing\" for connection configuration)\r\n");
        printf("  forward_proxy                      TLS forward proxy (use \"--incoming\" and \"--outgoing\" for connection configuration)\r\n");
        printf("  echo_server                        TLS echo server (use \"--incoming\" for connection configuration)\r\n");
        printf("  echo_server_proxy                  TLS echo server via reverse proxy (use \"--incoming\" for connection configuration)\r\n");
        printf("  tls_client                         TLS stdin client (use \"--outgoing\" for connection configuration)\r\n");
        printf("  network_tester                     TLS network tester (use \"--outgoing\" for connection configuration)\r\n");
        printf("  network_tester_proxy               TLS network tester via forward proxy (use \"--outgoing\" for connection configuration)\r\n");
        printf("  management_client                 Use Management Client (use \"--mgmt_path to provide config file path)\r\n");

        printf("\nConnection configuration:\r\n");
        printf("  --incoming <ip:>port               Configuration of the incoming TCP/TLS connection\r\n");
        printf("  --outgoing ip:port                 Configuration of the outgoing TCP/TLS connection\r\n");

        printf("\nCertificate/Key configuration:\r\n");
        printf("  --cert file_path                   Path to the certificate file\r\n");
        printf("  --key file_path                    Path to the private key file\r\n");
        printf("  --intermediate file_path           Path to an intermediate certificate file\r\n");
        printf("  --root file_path                   Path to the root certificate file\r\n");
        printf("  --additional_key file_path         Path to an additional private key file (hybrid signature mode)\r\n");

        printf("\nSecurity configuration:\r\n");
        printf("  --no_mutual_auth                   Disable mutual authentication (default enabled)\r\n");
        printf("  --use_null_cipher                  Use a cleartext cipher without encryption (default disabled)\r\n");
        printf("  --hybrid_signature mode            Mode for hybrid signatures: \"both\", \"native\", \"alternative\" (default: \"both\")\r\n");
        printf("  --key_exchange_alg algorithm       Key exchange algorithm: (default: \"secp384_mlkem768\")\r\n");
        printf("                                        Classic: \"secp256\", \"secp384\", \"secp521\", \"x25519\", \"x448\"\r\n");
        printf("                                        PQC: \"mlkem512\", \"mlkem768\", \"mlkem1024\"\r\n");
        printf("                                        Hybrid: \"secp256_mlkem512\", \"secp384_mlkem768\", \"secp256_mlkem768\"\r\n");
        printf("                                                \"secp521_mlkem1024\", \"secp384_mlkem1024\", \"x25519_mlkem512\"\r\n");
        printf("                                                \"x448_mlkem768\", \"x25519_mlkem768\"\r\n");

        printf("\nPKCS#11:\r\n");
        printf("  When using a secure element for long-term key storage, you have to supply the PKCS#11 key labels using the\n");
        printf("  arguments \"--key\" and \"--additionalKey\", prepending the string \"%s\" followed by the key label.\r\n", PKCS11_LABEL_IDENTIFIER);
        printf("  --p11_long_term_module file_path   Path to the secure element middleware for long-term key storage\r\n");
        printf("  --p11_long_term_pin pin            PIN for the secure element (default empty)\r\n");
        printf("  --p11_ephemeral_module file_path   Path to the PKCS#11 module for ephemeral cryptography\r\n");

        printf("\nNetwork tester configuration:\r\n");
        printf("  --test_num_handshakes num          Number of handshakes to perform in the test (default 1)\r\n");
        printf("  --test_handshake_delay num_ms      Delay between handshakes in milliseconds (default 0)\r\n");
        printf("  --test_num_messages num            Number of echo messages to send per handshake iteration (default 0)\r\n");
        printf("  --test_message_delay num_us        Delay between messages in microseconds (default 0)\r\n");
        printf("  --test_message_size num            Size of the echo message in bytes (default 1)\r\n");
        printf("  --test_output_path path            Path to the output file (filename will be appended)\r\n");
        printf("  --test_no_tls                      Disable TLS for test (plain TCP; default disabled)\r\n");
        printf("  --test_silent                      Disable progress printing\r\n");

        printf("\nGeneral:\r\n");
        printf("  --keylog_file file_path            Path to the keylog file for Wireshark\r\n");
        printf("  --verbose                          Enable verbose output\r\n");
        printf("  --debug                            Enable debug output\r\n");
        printf("  --help                             Display this help and exit\r\n");

        printf("\nManagement:\r\n");
        printf("  --mgmt_path                        Path to management config\r\n");
}

static int is_numeric(char const *str)
{
        while (*str)
        {
                if (!isdigit(*str))
                        return 0;
                str++;
        }

        return 1;
}

static int parse_ip_address(char *input, char **ip, uint16_t *port)
{
        /* Search for the first colon.
         *
         * 1) If non is found, we have either only an IPv4 address, or only an URI, or
         *    only a port number, e.g. "127.0.0.1", "localhost" or "4433".
         *
         * 2) If we only find a single colon, we have either an IPv4 address or an URI
         *    with a port number, e.g. "127.0.0.1:4433" or "localhost:4433".
         *
         * 3) If we find multiple colons, we have an IPv6 address. In this case, we have
         *    to check whether a port is also provided. If so, the IPv6 address must be
         *    wrapped in square brackets, e.g. "[::1]:4433".
         *    Otherwise, only an address is given, e.g. "::1".
         *
         * Rough code at the momemt, but it works for now...
         * ToDo: Refactor this code to make it more readable and maintainable.
         */
        char *first_colon = strchr(input, ':');

        if (first_colon == NULL)
        {
                /* First case */

                struct in_addr addr;
                if (net_addr_pton(AF_INET, input, &addr) == 1)
                {
                        /* We have an IPv4 address */
                        *ip = duplicate_string(input);
                        if (*ip == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for IP address");
                                return -1;
                        }
                        *port = 0;
                }
                else if (is_numeric(input))
                {
                        /* We have a port number */
                        *ip = NULL;
                        unsigned long new_port = strtoul(input, NULL, 10);
                        if ((new_port == 0) || (new_port > 65535))
                        {
                                LOG_ERROR("invalid port number %lu", new_port);
                                return -1;
                        }
                        *port = (uint16_t)new_port;
                }
                else
                {
                        /* We have an URI */
                        *ip = duplicate_string(input);
                        if (*ip == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for IP address");
                                return -1;
                        }
                        *port = 0;
                }
        }
        else
        {
                char *last_colon = strchr(first_colon + 1, ':');

                if (last_colon == NULL)
                {
                        /* Second case */

                        *first_colon = '\0';
                        *ip = duplicate_string(input);
                        if (*ip == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for IP address");
                                return -1;
                        }
                        unsigned long new_port = strtoul(first_colon + 1, NULL, 10);
                        if ((new_port == 0) || (new_port > 65535))
                        {
                                LOG_ERROR("invalid port number %lu", new_port);
                                return -1;
                        }
                        *port = (uint16_t)new_port;
                }
                else
                {
                        /* Third case */

                        /* Move to the last colon*/
                        char *tmp = last_colon;
                        while ((tmp = strchr(tmp + 1, ':')) != NULL)
                        {
                                last_colon = tmp;
                        }

                        if (*(last_colon - 1) == ']')
                        {
                                if (*input != '[')
                                {
                                        LOG_ERROR("invalid IPv6 address: %s", input);
                                        return -1;
                                }

                                /* Port is given */
                                *(last_colon - 1) = '\0';

                                *ip = duplicate_string(input + 1);
                                if (*ip == NULL)
                                {
                                        LOG_ERROR("unable to allocate memory for IP address");
                                        return -1;
                                }
                                unsigned long new_port = strtoul(last_colon + 1, NULL, 10);
                                if ((new_port == 0) || (new_port > 65535))
                                {
                                        LOG_ERROR("invalid port number %lu", new_port);
                                        return -1;
                                }
                                *port = (uint16_t)new_port;
                        }
                        else
                        {
                                /* Check if the user wrongly provided a port without square brackets */
                                *last_colon = '\0';
                                struct in6_addr addr;
                                if (net_addr_pton(AF_INET6, input, &addr) == 1)
                                {
                                        *last_colon = ':';
                                        LOG_ERROR("missing square brackets around IPv6 address before port: %s", input);
                                        return -1;
                                }
                                *last_colon = ':';

                                /* No port given */
                                *ip = duplicate_string(input);
                                if (*ip == NULL)
                                {
                                        LOG_ERROR("unable to allocate memory for IP address");
                                        return -1;
                                }
                                *port = 0;
                        }
                }
        }

        return 0;
}

static int readFile(const char *filePath, uint8_t **buffer, size_t bufferSize)
{
        uint8_t *destination = NULL;

        /* Open the file */
        FILE *file = fopen(filePath, "rb");

        if (file == NULL)
        {
                LOG_ERROR("file (%s) cannot be opened", filePath);
                return -1;
        }

        /* Get length of file */
        fseek(file, 0, SEEK_END);
        long fileSize = ftell(file);
        rewind(file);

        /* Allocate buffer for file content */
        if (*buffer == NULL && bufferSize == 0)
        {
                *buffer = (uint8_t *)malloc(fileSize);
                destination = *buffer;
        }
        else if (*buffer != NULL && bufferSize > 0)
        {
                *buffer = (uint8_t *)realloc(*buffer, bufferSize + fileSize);
                destination = *buffer + bufferSize;
        }

        if (*buffer == NULL)
        {
                LOG_ERROR("unable to allocate memory for file contents of %s", filePath);
                fclose(file);
                return -1;
        }

        /* Read file to buffer */
        int bytesRead = 0;
        while (bytesRead < fileSize)
        {
                int read = fread(destination + bytesRead, sizeof(uint8_t), fileSize - bytesRead, file);
                if (read < 0)
                {
                        LOG_ERROR("unable to read file (%s)", filePath);
                        fclose(file);
                        return -1;
                }
                bytesRead += read;
        }

        fclose(file);

        return bytesRead;
}

/* Read all certificate and key files from the paths provided in the `certs`
 * structure and store the data in the buffers. Memory is allocated internally
 * and must be freed by the user.
 *
 * Returns 0 on success, -1 on failure (error is printed on console). */
static int read_certificates(struct certificates *certs, enum application_role role)
{
        /* Read certificate chain */
        if (certs->certificate_path != NULL)
        {
                int cert_size = readFile(certs->certificate_path,
                                         &certs->chain_buffer, 0);
                if (cert_size < 0)
                {
                        LOG_ERROR("unable to read certificate from file %s", certs->certificate_path);
                        goto error;
                }

                certs->chain_buffer_size = cert_size;

                if (certs->intermediate_path != NULL)
                {
                        int inter_size = readFile(certs->intermediate_path,
                                                  &certs->chain_buffer, cert_size);
                        if (inter_size < 0)
                        {
                                LOG_ERROR("unable to read intermediate certificate from file %s", certs->intermediate_path);
                                goto error;
                        }

                        certs->chain_buffer_size += inter_size;
                }
        }
        else if ((role == ROLE_REVERSE_PROXY) || (role == ROLE_ECHO_SERVER))
        {
                LOG_ERROR("no certificate file specified");
                goto error;
        }

        /* Read private key */
        if (certs->private_key_path != 0)
        {
                if (strncmp(certs->private_key_path, PKCS11_LABEL_IDENTIFIER, PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                {
                        certs->key_buffer = (uint8_t *)duplicate_string(certs->private_key_path);
                        if (certs->key_buffer == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for key label");
                                goto error;
                        }
                        certs->key_buffer_size = strlen(certs->private_key_path) + 1;
                }
                else
                {
                        int key_size = readFile(certs->private_key_path,
                                                &certs->key_buffer, 0);
                        if (key_size < 0)
                        {
                                LOG_ERROR("unable to read private key from file %s", certs->private_key_path);
                                goto error;
                        }

                        certs->key_buffer_size = key_size;
                }
        }
        else if ((role == ROLE_REVERSE_PROXY) || (role == ROLE_ECHO_SERVER))
        {
                LOG_ERROR("no private key file specified");
                goto error;
        }

        /* Read addtional private key */
        if (certs->additional_key_path != 0)
        {
                if (strncmp(certs->additional_key_path, PKCS11_LABEL_IDENTIFIER, PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                {
                        certs->additional_key_buffer = (uint8_t *)duplicate_string(certs->additional_key_path);
                        if (certs->additional_key_buffer == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for key label");
                                goto error;
                        }
                        certs->additional_key_buffer_size = strlen(certs->additional_key_path) + 1;
                }
                else
                {
                        int key_size = readFile(certs->additional_key_path,
                                                &certs->additional_key_buffer, 0);
                        if (key_size < 0)
                        {
                                LOG_ERROR("unable to read private key from file %s", certs->additional_key_path);
                                goto error;
                        }

                        certs->additional_key_buffer_size = key_size;
                }
        }

        /* Read root certificate */
        if (certs->root_path != 0)
        {
                int root_size = readFile(certs->root_path,
                                         &certs->root_buffer, 0);
                if (root_size < 0)
                {
                        LOG_ERROR("unable to read root certificate from file %s", certs->root_path);
                        goto error;
                }

                certs->root_buffer_size = root_size;
        }
        else
        {
                LOG_ERROR("no root certificate file specified");
                goto error;
        }

        return 0;

error:
        free(certs->chain_buffer);
        free(certs->key_buffer);
        free(certs->additional_key_buffer);
        free(certs->root_buffer);

        return -1;
}
