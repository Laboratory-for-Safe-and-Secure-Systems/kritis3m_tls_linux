#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "logging.h"

#include "cli_parsing.h"


LOG_MODULE_CREATE(cli_parsing);


typedef struct certificates
{
        char const* certificate_path;
        char const* private_key_path;
        char const* additional_key_path;
        char const* intermediate_path;
        char const* root_path;

        uint8_t* chain_buffer; /* Entity and intermediate certificates */
        size_t chain_buffer_size;

        uint8_t* key_buffer;
        size_t key_buffer_size;

        uint8_t* additional_key_buffer;
        size_t additional_key_buffer_size;

        uint8_t* root_buffer;
        size_t root_buffer_size;
}
certificates;


static const struct option cli_options[] =
{
        { "incoming",           required_argument,    0, 'a' },
        { "outgoing",           required_argument,    0, 'b' },

        { "cert",               required_argument,    0, 'c' },
        { "key",                required_argument,    0, 'e' },
        { "intermediate",       required_argument,    0, 'f' },
        { "root",               required_argument,    0, 'g' },
        { "additionalKey",      required_argument,    0, 'i' },

        { "mutualAuth",         required_argument,    0, 'j' },
        { "noEncryption",       required_argument,    0, 'k' },
        { "hybrid_signature",   required_argument,    0, 'l' },
        { "keyExchangeAlg",     required_argument,    0, 'm' },

        { "middleware",         required_argument,    0, 'n' },

        { "keylogFile",         required_argument,    0, 'o' },
        { "verbose",            no_argument,          0, 'v' },
        { "debug",              no_argument,          0, 'd' },
        { "help",               no_argument,          0, 'h' },

        {NULL, 0, NULL, 0}
};


static void set_defaults(application_config* app_config, proxy_backend_config* proxy_backend_config,
                         proxy_config* proxy_config);
static int read_certificates(certificates* certs, enum application_role role);
static void print_help(char const* name);


/* Parse the provided argv array and store the information in the provided config variables.
 *
 * Returns 0 on success, +1 in case the help was printed and  -1 on failure (error is printed on console).
 */
int parse_cli_arguments(application_config* app_config, proxy_backend_config* proxy_backend_config,
                        proxy_config* proxy_config, size_t argc, char** argv)
{
        if ((app_config == NULL) || (proxy_config == NULL))
        {
                LOG_ERROR("mandatory argument missing for parse_cli_arguments()");
                return -1;
        }
        else if (argc < 2)
        {
                print_help(argv[0]);
                return 1;
        }

	/* Set default values */
        set_defaults(app_config, proxy_backend_config, proxy_config);

        struct certificates certs = {
                .certificate_path = NULL,
                .private_key_path = NULL,
                .additional_key_path = NULL,
                .intermediate_path = NULL,
                .root_path = NULL,
                .chain_buffer = NULL,
                .chain_buffer_size = 0,
                .key_buffer = NULL,
                .key_buffer_size = 0,
                .additional_key_buffer = NULL,
                .additional_key_buffer_size = 0,
                .root_buffer = NULL,
                .root_buffer_size = 0,
        };

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
        else if (strcmp(argv[1], "tls_client") == 0)
        {
                app_config->role = ROLE_TLS_CLIENT;
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
		int result = getopt_long(argc, argv, "a:b:c:e:f:g:i:j:k:l:m:n:o:vdh", cli_options, &index);

		if (result == -1)
		        break; /* end of list */

		switch (result)
		{
			case 'a':
			{
				/* Check if an IP address is provided */
				char* separator = strchr(optarg, ':');
				char* port_str = NULL;
				if (separator == NULL)
				{
					port_str = optarg;
					proxy_config->own_ip_address = duplicate_string("0.0.0.0");
				}
				else
				{
					*separator = '\0';
					proxy_config->own_ip_address = duplicate_string(optarg);
					port_str = separator + 1;
				}

				/* Parse the port */
				unsigned long new_port = strtoul(port_str, NULL, 10);
				if ((new_port == 0) || (new_port > 65535))
				{
					printf("invalid port number %lu\r\n", new_port);
					return -1;
				}
				proxy_config->listening_port = (uint16_t) new_port;
				break;
			}
			case 'b':
			{
				/* Parse the target IP address and port */
                                char* target_ip = strtok(optarg, ":");
				proxy_config->target_ip_address = duplicate_string(target_ip);
                                if (proxy_config->target_ip_address == NULL)
                                {
                                        LOG_ERROR("unable to allocate memory for target IP address");
                                        return -1;
                                }

				char* port_str = strtok(NULL, ":");
				if (port_str == NULL)
                                {
                                        LOG_ERROR("no port number provided");
                                        return -1;
                                }
                                unsigned long dest_port = strtoul(port_str, NULL, 10);
				if ((dest_port == 0) || (dest_port > 65535))
				{
					printf("invalid port number %lu\r\n", dest_port);
					return -1;
				}
				proxy_config->target_port = (uint16_t) dest_port;
				break;
			}
			case 'c':
				certs.certificate_path = optarg;
				break;
			case 'e':
				certs.private_key_path = optarg;
				break;
			case 'f':
				certs.intermediate_path = optarg;
				break;
			case 'g':
				certs.root_path = optarg;
				break;
                        case 'i':
                                certs.additional_key_path = optarg;
                                break;
                        case 'j':
                                proxy_config->tls_config.mutual_authentication = (bool) strtoul(optarg, NULL, 10);
                                break;
                        case 'k':
                                proxy_config->tls_config.no_encryption = (bool) strtoul(optarg, NULL, 10);
                                break;
                        case 'l':
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
                                proxy_config->tls_config.hybrid_signature_mode = mode;
                                break;
                        }
                        case 'm':
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
                                proxy_config->tls_config.key_exchange_method = kex_algo;
                                break;
                        }
                        case 'n':
                                proxy_config->tls_config.secure_element_middleware_path = duplicate_string(optarg);
                                if (proxy_config->tls_config.secure_element_middleware_path == NULL)
                                {
                                        LOG_ERROR("unable to allocate memory for secure element middleware path");
                                        return -1;
                                }
                                break;
                        case 'o':
                                proxy_config->tls_config.keylog_file = duplicate_string(optarg);
                                if (proxy_config->tls_config.keylog_file == NULL)
                                {
                                        LOG_ERROR("unable to allocate memory for keylog file path");
                                        return -1;
                                }
                                break;
                        case 'v':
                                app_config->log_level = LOG_LVL_INFO;
                                proxy_config->log_level = LOG_LVL_INFO;
                                if (proxy_backend_config != NULL)
                                        proxy_backend_config->log_level = LOG_LVL_INFO;
                                break;
                        case 'd':
                                app_config->log_level = LOG_LVL_DEBUG;
                                proxy_config->log_level = LOG_LVL_DEBUG;
                                if (proxy_backend_config != NULL)
                                        proxy_backend_config->log_level = LOG_LVL_DEBUG;
                                break;
			case 'h':
				print_help(argv[0]);
				return 1;
				break;
			default:
                                print_help(argv[0]);
                                return 1;
		}
    	}

	/* Read certificates */
    	if (read_certificates(&certs, app_config->role) != 0)
	{
        	return -1;
	}

	/* Set TLS config */
	proxy_config->tls_config.device_certificate_chain.buffer = certs.chain_buffer;
	proxy_config->tls_config.device_certificate_chain.size = certs.chain_buffer_size;
	proxy_config->tls_config.private_key.buffer = certs.key_buffer;
	proxy_config->tls_config.private_key.size = certs.key_buffer_size;
        proxy_config->tls_config.private_key.additional_key_buffer = certs.additional_key_buffer;
	proxy_config->tls_config.private_key.additional_key_size = certs.additional_key_buffer_size;
	proxy_config->tls_config.root_certificate.buffer = certs.root_buffer;
	proxy_config->tls_config.root_certificate.size = certs.root_buffer_size;

        return 0;
}


/* Cleanup any structures created during argument parsing */
void arguments_cleanup(application_config* app_config, proxy_backend_config* proxy_backend_config,
                       proxy_config* proxy_config)
{
        (void) app_config;
        (void) proxy_backend_config;

        /* Free memory of own IP address */
        if (proxy_config->own_ip_address != NULL)
        {
                free((void*) proxy_config->own_ip_address);
                proxy_config->own_ip_address = NULL;
        }

        /* Free memory of target IP address */
        if (proxy_config->target_ip_address != NULL)
        {
                free((void*) proxy_config->target_ip_address);
                proxy_config->target_ip_address = NULL;
        }

        /* Free memory of certificates and private key */
        if (proxy_config->tls_config.device_certificate_chain.buffer != NULL)
        {
                free((void*) proxy_config->tls_config.device_certificate_chain.buffer);
                proxy_config->tls_config.device_certificate_chain.buffer = NULL;
        }

        if (proxy_config->tls_config.private_key.buffer != NULL)
        {
                free((void*) proxy_config->tls_config.private_key.buffer);
                proxy_config->tls_config.private_key.buffer = NULL;
        }

        if (proxy_config->tls_config.private_key.additional_key_buffer != NULL)
        {
                free((void*) proxy_config->tls_config.private_key.additional_key_buffer);
                proxy_config->tls_config.private_key.additional_key_buffer = NULL;
        }

        if (proxy_config->tls_config.root_certificate.buffer != NULL)
        {
                free((void*) proxy_config->tls_config.root_certificate.buffer);
                proxy_config->tls_config.root_certificate.buffer = NULL;
        }

        if (proxy_config->tls_config.secure_element_middleware_path != NULL)
        {
                free((void*) proxy_config->tls_config.secure_element_middleware_path);
                proxy_config->tls_config.secure_element_middleware_path = NULL;
        }

        if (proxy_config->tls_config.keylog_file != NULL)
        {
                free((void*) proxy_config->tls_config.keylog_file);
                proxy_config->tls_config.keylog_file = NULL;
        }
}


/* Helper method to dynamically duplicate a string */
char* duplicate_string(char const* source)
{
        char* dest = (char*) malloc(strlen(source) + 1);
        if (dest == NULL)
        {
                LOG_ERROR("unable to allocate memory for string duplication");
                return NULL;
        }
        strcpy(dest, source);

        return dest;
}


static void set_defaults(application_config* app_config, proxy_backend_config* proxy_backend_config,
                         proxy_config* proxy_config)
{
        int32_t default_log_level = LOG_LVL_WARN;

        /* Application config */
        app_config->role = NOT_SET;
        app_config->log_level = default_log_level;

        /* Proxy backend config */
        if (proxy_backend_config != NULL)
        {
                proxy_backend_config->log_level = default_log_level;
        }

        /* Proxy config */
        memset(proxy_config, 0, sizeof(*proxy_config));
        proxy_config->own_ip_address = NULL;
        proxy_config->listening_port = 0;
        proxy_config->target_ip_address = NULL;
        proxy_config->target_port = 0;
        proxy_config->tls_config.mutual_authentication = true;
        proxy_config->tls_config.no_encryption = false;
        proxy_config->tls_config.hybrid_signature_mode = ASL_HYBRID_SIGNATURE_MODE_DEFAULT;
        proxy_config->tls_config.key_exchange_method = ASL_KEX_DEFAULT;
        proxy_config->tls_config.secure_element_middleware_path = NULL;
        proxy_config->tls_config.device_certificate_chain.buffer = NULL;
        proxy_config->tls_config.device_certificate_chain.size = 0;
        proxy_config->tls_config.private_key.buffer = NULL;
        proxy_config->tls_config.private_key.size = 0;
        proxy_config->tls_config.private_key.additional_key_buffer = NULL;
        proxy_config->tls_config.private_key.additional_key_size = 0;
        proxy_config->tls_config.root_certificate.buffer = NULL;
        proxy_config->tls_config.root_certificate.size = 0;
#if defined(HAVE_SECRET_CALLBACK)
        proxy_config->tls_config.keylog_file = NULL;
#endif
        proxy_config->log_level = default_log_level;
}


static void print_help(char const* name)
{
        printf("Usage: %s ROLE [OPTIONS]\r\n", name);
        printf("Roles:\r\n");
        printf("  reverse_proxy                    TLS reverse proxy (use \"--incoming\" and \"--outgoing\" for connection configuration)\r\n");
        printf("  forward_proxy                    TLS forward proxy (use \"--incoming\" and \"--outgoing\" for connection configuration)\r\n");
        printf("  echo_server                      TLS echo server (use \"--incoming\" for connection configuration)\r\n");
        printf("  tls_client                       TLS stdin client (use \"--outgoing\" for connection configuration)\r\n");

        printf("\nConnection configuration:\r\n");
        printf("  --incoming <ip:>port             configuration of the incoming TCP/TLS connection\r\n");
        printf("  --outgoing ip:port               configuration of the outgoing TCP/TLS connection\r\n");

        printf("\nCertificate/Key configuration:\r\n");
        printf("  --cert file_path                 path to the certificate file\r\n");
        printf("  --key file_path                  path to the private key file\r\n");
        printf("  --intermediate file_path         path to an intermediate certificate file\r\n");
        printf("  --root file_path                 path to the root certificate file\r\n");
        printf("  --additionalKey file_path        path to an additional private key file (hybrid signature mode)\r\n");

        printf("\nSecurity configuration:\r\n");
        printf("  --mutualAuth 0|1                 enable or disable mutual authentication (default enabled)\r\n");
        printf("  --noEncryption 0|1               enable or disable encryption (default enabled)\r\n");
        printf("  --hybrid_signature mode          mode for hybrid signatures: \"both\", \"native\", \"alternative\" (default: \"both\")\r\n");
        printf("  --keyExchangeAlg algorithm       key exchange algorithm: (default: \"secp384_mlkem768\")\r\n");
        printf("                                      classic: \"secp256\", \"secp384\", \"secp521\", \"x25519\", \"x448\"\r\n");
        printf("                                      PQC: \"mlkem512\", \"mlkem768\", \"mlkem1024\"\r\n");
        printf("                                      hybrid: \"secp256_mlkem512\", \"secp384_mlkem768\", \"secp256_mlkem768\"\r\n");
        printf("                                              \"secp521_mlkem1024\", \"secp384_mlkem1024\", \"x25519_mlkem512\"\r\n");
        printf("                                              \"x448_mlkem768\", \"x25519_mlkem768\"\r\n");

        printf("\nSecure Element:\n");
        printf("  When using a secure element for key storage, you have to supply the PKCS#11 key labels using the arguments\n");
        printf("  \"--key\" and \"--additionalKey\" prepending the string \"%s\" followed by the key label.\n", PKCS11_LABEL_IDENTIFIER);
        printf("  --middleware file_path           path to the secure element middleware\r\n");

        printf("\nGeneral:\n");
        printf("  --keylogFile file_path           path to the keylog file for Wireshark\r\n");
        printf("  --verbose                        enable verbose output\r\n");
        printf("  --debug                          enable debug output\r\n");
        printf("  --help                           display this help and exit\r\n");
}


static int readFile(const char* filePath, uint8_t** buffer, size_t bufferSize)
{
        uint8_t* destination = NULL;

        /* Open the file */
        FILE* file = fopen(filePath, "r");

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
                *buffer = (uint8_t*) malloc(fileSize);
                destination = *buffer;
        }
        else if (*buffer != NULL && bufferSize > 0)
        {
                *buffer = (uint8_t*) realloc(*buffer, bufferSize + fileSize);
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
static int read_certificates(struct certificates* certs, enum application_role role)
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
                        certs->key_buffer = (uint8_t*) duplicate_string(certs->private_key_path);
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
                        certs->additional_key_buffer = (uint8_t*) duplicate_string(certs->additional_key_path);
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
