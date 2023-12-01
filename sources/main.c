
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>

#include "networking.h"
#include "logging.h"
#include "wolfssl.h"
#include "tls_echo_server.h"

#include "certificates.h"

LOG_MODULE_REGISTER(KRITIS3M_TLS);


#define fatal(msg, ...) { \
		LOG_ERR("Error: " msg "", ##__VA_ARGS__); \
		exit(-1); \
	}


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


void init(void)
{
	initialize_network_interfaces();

	/* Initalize the tls_echo_server application */
	int ret = tls_echo_server_init();
	if (ret != 0)
		fatal("unable to initialize tls_echo_server application");


	/* Initialize WolfSSL */
	struct wolfssl_library_configuration config = {
		.loggingEnabled = false,
	};

	ret = wolfssl_init(&config);
	if (ret != 0)
		fatal("unable to initialize WolfSSL");

	/* Run the echo server (asynchronously) */
	ret = tls_echo_server_run();
	if (ret != 0)
		fatal("unable to run tls_echo_server application");
}


static const struct option long_options[] =
{
    { "port",           required_argument, 0, 'p' },
    { "cert",           required_argument, 0, 'c' },
    { "key",            required_argument, 0, 'k' },
    { "intermediate",   required_argument, 0, 'i' },
    { "root",           required_argument, 0, 'r' },
    0
};

int main(int argc, char** argv)
{
	init();

    int index = -1;

    char* cert = NULL;
    char* key = NULL;
    char* intermediate = NULL;
    char* root = NULL;

    /* The new TLS server config */
	struct tls_server_config tls_echo_server_config = {
		.ip_address = "127.0.0.1",
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
        },
	};

    static const size_t certificate_chain_buffer_size = 32 * 1024;
    static const size_t private_key_buffer_size = 16 * 1024;
    static const size_t root_certificate_buffer_size = 16 * 1024;

    /* Parse arguments */
    while (true)
    {
        int result = getopt_long(argc, argv, "p:c:k:i:r:", long_options, &index);

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
                tls_echo_server_config.listening_port = (uint16_t) new_port;
                break;
            case 'c':
                cert = optarg;
                break;
            case 'k':
                key = optarg;
                break;
            case 'i':
                intermediate = optarg;
                break;
            case 'r':
                root = optarg;
                break;
            default:
                printf("unknown option: %c\n", result);
                break;
        }
    }

    /* Allocate memory for the files to read */
    tls_echo_server_config.tls_config.device_certificate_chain.buffer = (uint8_t*) malloc(certificate_chain_buffer_size);
    if (tls_echo_server_config.tls_config.device_certificate_chain.buffer == NULL)
    {
        LOG_ERR("unable to allocate memory for certificate chain");
        exit(-1);
    }

    tls_echo_server_config.tls_config.private_key.buffer = (uint8_t*) malloc(private_key_buffer_size);
    if (tls_echo_server_config.tls_config.private_key.buffer == NULL)
    {
        LOG_ERR("unable to allocate memory for private key");
        exit(-1);
    }

    tls_echo_server_config.tls_config.root_certificate.buffer = (uint8_t*) malloc(root_certificate_buffer_size);
    if (tls_echo_server_config.tls_config.root_certificate.buffer == NULL)
    {
        LOG_ERR("unable to allocate memory for root certificate");
        exit(-1);
    }

    /* Read certificate chain */
    if (cert != NULL)
    {
        int cert_size = readFile(cert,
                                 tls_echo_server_config.tls_config.device_certificate_chain.buffer,
                                 certificate_chain_buffer_size);
        if (cert_size < 0)
        {
            LOG_ERR("unable to read certificate from file %s", cert);
            exit(-1);
        }

        tls_echo_server_config.tls_config.device_certificate_chain.size = cert_size;

        if (intermediate != NULL)
        {
            int inter_size = readFile(intermediate,
                                      tls_echo_server_config.tls_config.device_certificate_chain.buffer + cert_size,
                                      certificate_chain_buffer_size - cert_size);
            if (inter_size < 0)
            {
                LOG_ERR("unable to read intermediate certificate from file %s", intermediate);
                exit(-1);
            }

            tls_echo_server_config.tls_config.device_certificate_chain.size += inter_size;
        }
    }
    else
    {
        LOG_ERR("no certificate file specified");
        exit(-1);
    }

    /* Read private key */
    if (key != 0)
    {
        int key_size = readFile(key,
                                tls_echo_server_config.tls_config.private_key.buffer,
                                private_key_buffer_size);
        if (key_size < 0)
        {
            LOG_ERR("unable to read private key from file %s", key);
            exit(-1);
        }

        tls_echo_server_config.tls_config.private_key.size = key_size;
    }
    else
    {
        LOG_ERR("no private key file specified");
        exit(-1);
    }

    /* Read root certificate */
    if (root != 0)
    {
        int root_size = readFile(root,
                                 tls_echo_server_config.tls_config.root_certificate.buffer,
                                 root_certificate_buffer_size);
        if (root_size < 0)
        {
            LOG_ERR("unable to read root certificate from file %s", root);
            exit(-1);
        }

        tls_echo_server_config.tls_config.root_certificate.size = root_size;
    }
    else
    {
        LOG_ERR("no root certificate file specified");
        exit(-1);
    }

	/* Add the new TLS echo server to the application backend */
	int id = tls_echo_server_start(&tls_echo_server_config);
	if (id < 0)
	{
		LOG_ERR("unable to start TLS echo server");
		return -EINVAL;
	}
	
	LOG_INF("started TLS echo server with id %d", id);


    while (true)
    {
        sleep(100);
    }

	return 0;
}
