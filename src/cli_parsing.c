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
        { "key",                required_argument,    0, 'k' },
        { "intermediate",       required_argument,    0, 'i' },
        { "root",               required_argument,    0, 'r' },
        { "additionalKey",      required_argument,    0, 'l' },
        { "mutualAuth",         required_argument,    0, 'n' },
        { "noEncryption",       required_argument,    0, 'o' },
        { "hybrid_signature",   required_argument,    0, 'q' },
        { "use_secure_element", required_argument,    0, 's' },
        { "middleware_path",    required_argument,    0, 'm' },
        { "se_import_keys",     required_argument,    0, 'p' },
        { "verbose",            no_argument,          0, 't' },
        { "debug",              no_argument,          0, 'd' },
        { "keylogFile",         required_argument,    0, 'j' },
        { "help",               no_argument,          0, 'h' },
        {NULL, 0, NULL, 0}
};


static void set_defaults(application_config* app_config, asl_configuration* asl_config,
                         proxy_backend_config* proxy_backend_config, proxy_config* proxy_config);
static int read_certificates(certificates* certs, enum application_role role);
static void print_help(char const* name);


/* Parse the provided argv array and store the information in the provided config variables.
 *
 * Returns 0 on success, +1 in case the help was printed and  -1 on failure (error is printed on console).
 */
int parse_cli_arguments(application_config* app_config, asl_configuration* asl_config,
                        proxy_backend_config* proxy_backend_config, proxy_config* proxy_config,
                        size_t argc, char** argv)
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
        set_defaults(app_config, asl_config, proxy_backend_config, proxy_config);

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
        else if (strcmp(argv[1], "echo_client") == 0)
        {
                app_config->role = ROLE_ECHO_CLIENT;
        }
        else
        {
                LOG_ERROR("invalid role: %s", argv[1]);
                print_help(argv[0]);
                return -1;

        }

	/* Parse arguments */
	int index = 0;
	while (true)
	{
		int result = getopt_long(argc, argv, "a:b:c:k:i:r:l:n:o:q:s:m:p:tdj:h", cli_options, &index);

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
					proxy_config->own_ip_address = "0.0.0.0";
				}
				else
				{
					*separator = '\0';
					proxy_config->own_ip_address = optarg;
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
				proxy_config->target_ip_address = strtok(optarg, ":");

				char* port_str = strtok(NULL, ":");
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
			case 'k':
				certs.private_key_path = optarg;
				break;
			case 'i':
				certs.intermediate_path = optarg;
				break;
			case 'r':
				certs.root_path = optarg;
				break;
                        case 'l':
                                certs.additional_key_path = optarg;
                                break;
                        case 'n':
                                proxy_config->tls_config.mutual_authentication = (bool) strtoul(optarg, NULL, 10);
                                break;
                        case 'o':
                                proxy_config->tls_config.no_encryption = (bool) strtoul(optarg, NULL, 10);
                                break;
                        case 'q':
                        {
                                enum asl_hybrid_signature_mode mode;
                                if (strcmp(optarg, "both") == 0)
                                        mode = HYBRID_SIGNATURE_MODE_BOTH;
                                else if (strcmp(optarg, "native") == 0)
                                        mode = HYBRID_SIGNATURE_MODE_NATIVE;
                                else if (strcmp(optarg, "alternative") == 0)
                                        mode = HYBRID_SIGNATURE_MODE_ALTERNATIVE;
                                else
                                {
                                        printf("invalid hybrid signature mode: %s\r\n", optarg);
                                        print_help(argv[0]);
                                        return 1;
                                }
                                proxy_config->tls_config.hybrid_signature_mode = mode;
                                break;
                        }
			case 's':
                                bool use_secure_element = (bool) strtoul(optarg, NULL, 10);
                                proxy_config->tls_config.use_secure_element = use_secure_element;
				if (asl_config != NULL)
                                        asl_config->secure_element_support = use_secure_element;
				break;
                        case 'm':
                                if (asl_config != NULL)
                                        asl_config->secure_element_middleware_path = optarg;
                                break;
                        case 'p':
                                proxy_config->tls_config.secure_element_import_keys = (bool) strtoul(optarg, NULL, 10);
                                break;
                        case 't':
                                app_config->log_level = LOG_LVL_INFO;
                                proxy_config->log_level = LOG_LVL_INFO;
                                if (asl_config != NULL)
                                {
                                        asl_config->logging_enabled = true;
                                        asl_config->log_level = LOG_LVL_INFO;
                                }
                                if (proxy_backend_config != NULL)
                                {
                                        proxy_backend_config->log_level = LOG_LVL_INFO;
                                }
                                break;
                        case 'd':
                                app_config->log_level = LOG_LVL_DEBUG;
                                proxy_config->log_level = LOG_LVL_DEBUG;
                                if (asl_config != NULL)
                                {
                                        asl_config->logging_enabled = true;
                                        asl_config->log_level = LOG_LVL_DEBUG;
                                }
                                if (proxy_backend_config != NULL)
                                {
                                        proxy_backend_config->log_level = LOG_LVL_DEBUG;
                                }
                                break;
                        case 'j':
                                proxy_config->tls_config.keylog_file = optarg;
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


static void set_defaults(application_config* app_config, asl_configuration* asl_config,
                         proxy_backend_config* proxy_backend_config, proxy_config* proxy_config)
{
        int32_t default_log_level = LOG_LVL_WARN;

        /* Application config */
        app_config->role = NOT_SET;
        app_config->log_level = default_log_level;

        /* ASL config */
        if (asl_config != NULL)
        {
                memset(asl_config, 0, sizeof(*asl_config));
                asl_config->logging_enabled = false;
                asl_config->log_level = default_log_level;
                asl_config->secure_element_support = false;
                asl_config->secure_element_middleware_path = NULL;
        }

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
        proxy_config->tls_config.use_secure_element = false;
        proxy_config->tls_config.secure_element_import_keys = false;
        proxy_config->tls_config.hybrid_signature_mode = HYBRID_SIGNATURE_MODE_BOTH;
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
        printf("Roles:\r\n\n");
        printf("  reverse_proxy                    TLS reverse proxy (use --incoming and --outgoing for connection configuration)\r\n");
        printf("  forward_proxy                    TLS forward proxy (use --incoming and --outgoing for connection configuration)\r\n");
        printf("  echo_server                      TLS echo server (use --incoming for connection configuration)\r\n");
        printf("  echo_client                      TLS stdin client (use --outgoing for connection configuration)\r\n");
        printf("\nConnection configuration:\r\n\n");
        printf("  --incoming <ip:>port             configuration of the incoming TCP/TLS connection\r\n");
        printf("  --outgoing ip:port               configuration of the outgoing TCP/TLS connection\r\n");
        printf("\nOptions:\r\n\n");
        printf("  --cert file_path                 path to the certificate file\r\n");
        printf("  --key file_path                  path to the private key file\r\n");
        printf("  --intermediate file_path         path to an intermediate certificate file\r\n");
        printf("  --root file_path                 path to the root certificate file\r\n");
        printf("  --additionalKey file_path        path to an additional private key file (hybrid signature mode)\r\n\n");
        printf("  --mutualAuth 0|1                 enable or disable mutual authentication (default enabled)\r\n");
        printf("  --noEncryption 0|1               enable or disable encryption (default enabled)\r\n");
        printf("  --hybrid_signature mode          mode for hybrid signatures: both, native, alternative (default: both)\r\n\n");
        printf("  --use_secure_element 0|1         use secure element (default disabled)\r\n");
        printf("  --middleware_path file_path      path to the secure element middleware\r\n");
        printf("  --se_import_keys 0|1             import provided keys into secure element (default disabled)\r\n\n");
        printf("  --verbose                        enable verbose output\r\n");
        printf("  --debug                          enable debug output\r\n");
        printf("  --keylogFile file_path           path to the keylog file for Wireshark\r\n\n");
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
                int key_size = readFile(certs->private_key_path,
                                        &certs->key_buffer, 0);
                if (key_size < 0)
                {
                        LOG_ERROR("unable to read private key from file %s", certs->private_key_path);
                        goto error;
                }

                certs->key_buffer_size = key_size;
        }
        else if ((role == ROLE_REVERSE_PROXY) || (role == ROLE_ECHO_SERVER))
        {
                LOG_ERROR("no private key file specified");
                goto error;
        }

        /* Read addtional private key */
        if (certs->additional_key_path != 0)
        {
                int key_size = readFile(certs->additional_key_path,
                                        &certs->additional_key_buffer, 0);
                if (key_size < 0)
                {
                        LOG_ERROR("unable to read private key from file %s", certs->private_key_path);
                        goto error;
                }

                certs->additional_key_buffer_size = key_size;
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
