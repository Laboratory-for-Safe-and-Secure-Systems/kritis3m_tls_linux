
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>

#include "networking.h"
#include "logging.h"
#include "wolfssl.h"
#include "tls_proxy.h"

#include "certificates.h"

LOG_MODULE_REGISTER(KRITIS3M_TLS);


#define fatal(msg, ...) { \
		LOG_ERR("Error: " msg "", ##__VA_ARGS__); \
		exit(-1); \
	}


volatile __sig_atomic_t running = true;

int readFile(const char* filePath, uint8_t* buffer, size_t bufferSize)
{
    /* Open the file */
    FILE* file = fopen(filePath, "r");
    
    if (file == NULL)
    {
        LOG_ERR("file (%s) cannot be opened", filePath);
        return -1;
    }
    
    /* Get length of file */
    fseek(file, 0, SEEK_END);
    int fileSize = ftell(file);
    rewind(file);

    if (fileSize > bufferSize)
    {
        LOG_ERR("file (%s) is too large for internal buffer", filePath);
        fclose(file);
        return -1;
    }
    
    /* Read file to buffer */
    int bytesRead = 0;
    while (bytesRead < fileSize)
    {
        int read = fread(buffer + bytesRead, sizeof(uint8_t), fileSize - bytesRead, file);
        if (read < 0)
        {
            LOG_ERR("unable to read file (%s)", filePath);
            fclose(file);
            return -1;
        }
        bytesRead += read;
    }
    
    fclose(file);

    return bytesRead;
}


static void signal_handler(int signo)
{
    /* Indicate the main process to stop */
    running = false;
}

void init(void)
{
	initialize_network_interfaces();

    /* Install the signal handler */
    struct sigaction signal_action;
    sigemptyset (&signal_action.sa_mask);
    signal_action.sa_handler = signal_handler;
    sigaction(SIGINT, &signal_action, NULL);

	/* Initalize the tls_proxy application */
	int ret = tls_proxy_init();
	if (ret != 0)
		fatal("unable to initialize tls_echo_server application");
}


static const struct option long_options[] =
{
    { "port",           required_argument, 0, 'p' },
    { "cert",           required_argument, 0, 'c' },
    { "key",            required_argument, 0, 'k' },
    { "intermediate",   required_argument, 0, 'i' },
    { "root",           required_argument, 0, 'r' },
    { "secure_element", required_argument, 0, 's' },
    { "help",           no_argument,       0, 'h' },
    0
};

int main(int argc, char** argv)
{
	init();

    int index = -1;

    /* Variables for the user supplied paths */
    char* cert_path = NULL;
    char* key_path = NULL;
    char* intermediate_path = NULL;
    char* root_path = NULL;

    /* Variables for the actual read data */
    uint8_t* cert_chain_buffer = NULL; /* Entity certificate and intermediate */
    uint8_t* key_buffer = NULL;
    uint8_t* root_buffer = NULL;

    /* WolfSSL config */
    struct wolfssl_library_configuration wolfssl_config = {
		.loggingEnabled = true,
        .secure_element_middleware_path = NULL,
	};

    /* The new TLS reverse proxy config */
	struct reverse_proxy_config tls_reverse_proxy_config = {
		.own_ip_address = "127.0.0.1",
		.listening_port = 0,
        .tls_config = {
            .device_certificate_chain = {
                .buffer = NULL,
                .size = 0,
            },
            .private_key = {
                .buffer = NULL,
                .size = 0,
            },
            .root_certificate = {
                .buffer = NULL,
                .size = 0,
            },
            .use_secure_element = false,
        },
	};

    static const size_t certificate_chain_buffer_size = 32 * 1024;
    static const size_t private_key_buffer_size = 16 * 1024;
    static const size_t root_certificate_buffer_size = 16 * 1024;

    /* Parse arguments */
    while (true)
    {
        int result = getopt_long(argc, argv, "p:c:k:i:r:s:h", long_options, &index);

        if (result == -1) break; /* end of list */

        switch (result)
        {
            case 'p':
                unsigned long new_port = strtoul(optarg, NULL, 10);
                if ((new_port == 0) || (new_port > 65535))
                {
                    LOG_ERR("invalid port number %lu", new_port);
                    exit(-1);
                }
                tls_reverse_proxy_config.listening_port = (uint16_t) new_port;
                break;
            case 'c':
                cert_path = optarg;
                break;
            case 'k':
                key_path = optarg;
                break;
            case 'i':
                intermediate_path = optarg;
                break;
            case 'r':
                root_path = optarg;
                break;
            case 's':
                tls_reverse_proxy_config.tls_config.use_secure_element = true;
                wolfssl_config.secure_element_middleware_path = optarg;
                break;
            case 'h': 
                printf("Usage: %s [OPTIONS]\n", argv[0]);
                printf("Options:\n");
                printf("  -p, --port PORT                   listening port of the TLS echo server\n");
                printf("  -c, --cert <file_path>            path to the certificate file\n");
                printf("  -k, --key <file_path>             path to the private key file\n");
                printf("  -i, --intermediate <file_path>    \n");
                printf("                                    path to an intermediate certificate file\n");
                printf("  -r, --root <file_path>            path to the root certificate file\n");
                printf("  -s, --secure_element <file_path>  use secure element with the provided middleware\n");
                printf("  -h, --help                        display this help and exit\n");
                exit(0);
                break;
            default:
                printf("unknown option: %c\n", result);
                break;
        }
    }

    /* Initialize WolfSSL */
	int ret = wolfssl_init(&wolfssl_config);
	if (ret != 0)
		fatal("unable to initialize WolfSSL");

	/* Run the proxy (asynchronously) */
	ret = tls_proxy_run();
	if (ret != 0)
		fatal("unable to run tls proxy application");


    /* Allocate memory for the files to read */
    cert_chain_buffer = (uint8_t*) malloc(certificate_chain_buffer_size);
    if (cert_chain_buffer == NULL)
    {
        LOG_ERR("unable to allocate memory for certificate chain");
        exit(-1);
    }

    key_buffer = (uint8_t*) malloc(private_key_buffer_size);
    if (key_buffer == NULL)
    {
        LOG_ERR("unable to allocate memory for private key");
        exit(-1);
    }

    root_buffer = (uint8_t*) malloc(root_certificate_buffer_size);
    if (root_buffer == NULL)
    {
        LOG_ERR("unable to allocate memory for root certificate");
        exit(-1);
    }

    /* Read certificate chain */
    if (cert_path != NULL)
    {
        int cert_size = readFile(cert_path,
                                 cert_chain_buffer,
                                 certificate_chain_buffer_size);
        if (cert_size < 0)
        {
            LOG_ERR("unable to read certificate from file %s", cert_path);
            exit(-1);
        }

        tls_reverse_proxy_config.tls_config.device_certificate_chain.size = cert_size;

        if (intermediate_path != NULL)
        {
            int inter_size = readFile(intermediate_path,
                                      cert_chain_buffer + cert_size,
                                      certificate_chain_buffer_size - cert_size);
            if (inter_size < 0)
            {
                LOG_ERR("unable to read intermediate certificate from file %s", intermediate_path);
                exit(-1);
            }

            tls_reverse_proxy_config.tls_config.device_certificate_chain.size += inter_size;
        }

        tls_reverse_proxy_config.tls_config.device_certificate_chain.buffer = cert_chain_buffer;
    }
    else
    {
        LOG_ERR("no certificate file specified");
        exit(-1);
    }

    /* Read private key */
    if (key_path != 0)
    {
        int key_size = readFile(key_path,
                                key_buffer,
                                private_key_buffer_size);
        if (key_size < 0)
        {
            LOG_ERR("unable to read private key from file %s", key_path);
            exit(-1);
        }

        tls_reverse_proxy_config.tls_config.private_key.buffer = key_buffer;
        tls_reverse_proxy_config.tls_config.private_key.size = key_size;

        if (tls_reverse_proxy_config.tls_config.use_secure_element == true)
        {
            /* Temporary solution */
            LOG_INF("Importing private key into secure element");
        }
    }
    else if (tls_reverse_proxy_config.tls_config.use_secure_element == true)
    {
        LOG_INF("Using private key on secure elment");
    }
    else
    {
        LOG_ERR("no private key file specified");
        exit(-1);
    }

    /* Read root certificate */
    if (root_path != 0)
    {
        int root_size = readFile(root_path,
                                 root_buffer,
                                 root_certificate_buffer_size);
        if (root_size < 0)
        {
            LOG_ERR("unable to read root certificate from file %s", root_path);
            exit(-1);
        }

        tls_reverse_proxy_config.tls_config.root_certificate.buffer = root_buffer;
        tls_reverse_proxy_config.tls_config.root_certificate.size = root_size;
    }
    else
    {
        LOG_ERR("no root certificate file specified");
        exit(-1);
    }

	/* Add the new TLS reverse proxy to the application backend */
	int id = tls_reverse_proxy_start(&tls_reverse_proxy_config);
	if (id < 0)
	{
		LOG_ERR("unable to start TLS reverse proxy");
		return -EINVAL;
	}
	
	LOG_INF("started TLS reverse proxy with id %d", id);


    while (running)
    {
        sleep(1);
    }

    printf("Terminating...\n");

    /* We only land here if we received a terminate signal. First, we
     * kill the running server (especially its running client thread, if
     * present). Then, we kill the actual application thread. */
    tls_reverse_proxy_stop(id);
    tls_proxy_terminate();

	return 0;
}
