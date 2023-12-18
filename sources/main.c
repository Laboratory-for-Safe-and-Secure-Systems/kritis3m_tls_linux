
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
#include "poll_set.h"

#include "tls_proxy.h"
#include "tcp_echo_server.h"
#include "tcp_client_stdin_bridge.h"

#include "certificate_handling.h"


LOG_MODULE_REGISTER(KRITIS3M_TLS);


#define ANY_IP "0.0.0.0"

#define LOCAL_ECHO_SERVER_IP "127.0.0.1"
#define LOCAL_ECHO_SERVER_PORT 40000

#define LOCAL_STDIN_CLIENT_BRIDGE_IP "127.0.0.1"
#define LOCAL_STDIN_CLIENT_BRIDGE_PORT 40001


#define fatal(msg, ...) { \
		LOG_ERR("Error: " msg "", ##__VA_ARGS__); \
		exit(-1); \
	}


enum application_role
{
    NOT_SET,
    ROLE_REVERSE_PROXY,
    ROLE_FORWARD_PROXY,
    ROLE_ECHO_SERVER,
    ROLE_ECHO_CLIENT,
};


volatile __sig_atomic_t running = true;

static void signal_handler(int signo)
{
    /* Indicate the main process to stop */
    running = false;
}


static const struct option long_options[] =
{
    { "echo_server",    required_argument, 0, 'e' },
    { "echo_client",    required_argument, 0, 'f' },
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
	initialize_network_interfaces();

    /* Install the signal handler */
    struct sigaction signal_action;
    sigemptyset(&signal_action.sa_mask);
    signal_action.sa_handler = signal_handler;
    sigaction(SIGINT, &signal_action, NULL);

	/* Initalize the tls_proxy application */
	int ret = tls_proxy_backend_init();
	if (ret != 0)
		fatal("unable to initialize tls_echo_server application");

    int index = -1;

    enum application_role role = NOT_SET;


    /* WolfSSL config */
    struct wolfssl_library_configuration wolfssl_config = {
		.loggingEnabled = true,
        .secure_element_middleware_path = NULL,
	};

    /* Certificate structure */
    struct certificates certs = {
        .certificate_path = NULL,
        .private_key_path = NULL,
        .intermediate_path = NULL,
        .root_path = NULL,

        .cert_chain_buffer = NULL, /* Entity certificate and intermediate */
        .cert_chain_buffer_size = 0,
        .key_buffer = NULL,
        .key_buffer_size = 0,
        .root_buffer = NULL,
        .root_buffer_size = 0,
    };

    /* TLS proxy config */
	struct proxy_config tls_proxy_config = {
		.own_ip_address = NULL,
		.listening_port = 0,
        .target_ip_address = NULL,
        .target_port = 0,
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

    /* TCP echo server config */
    struct tcp_echo_server_config tcp_echo_server_config = {
        .own_ip_address = LOCAL_ECHO_SERVER_IP,
        .listening_port = LOCAL_ECHO_SERVER_PORT,
    };

    /* TCP client stdin bridge config */
    struct tcp_client_stdin_bridge_config tcp_client_stdin_bridge_config = {
        .target_ip_address = LOCAL_STDIN_CLIENT_BRIDGE_IP,
        .target_port = LOCAL_STDIN_CLIENT_BRIDGE_PORT,
    };

    /* Parse arguments */
    while (true)
    {
        int result = getopt_long(argc, argv, "e:f:c:k:i:r:s:h", long_options, &index);

        if (result == -1) break; /* end of list */

        switch (result)
        {
            case 'e':
                if (role != NOT_SET)
                {
                    LOG_ERR("the following options may be used only exclusively:");
                    LOG_ERR("reverse_proxy, forward_proxy, echo_server, echo_client");
                    exit(-1);
                }

                unsigned long new_port = strtoul(optarg, NULL, 10);
                if ((new_port == 0) || (new_port > 65535))
                {
                    LOG_ERR("invalid port number %lu", new_port);
                    exit(-1);
                }

                tls_proxy_config.own_ip_address = ANY_IP;
                tls_proxy_config.listening_port = (uint16_t) new_port;
                tls_proxy_config.target_ip_address = LOCAL_ECHO_SERVER_IP;
                tls_proxy_config.target_port = LOCAL_ECHO_SERVER_PORT;

                role = ROLE_ECHO_SERVER;
                break;
            case 'f':
                if (role != NOT_SET)
                {
                    LOG_ERR("the following options may be used only exclusively:");
                    LOG_ERR("reverse_proxy, forward_proxy, echo_server, echo_client");
                    exit(-1);
                }
                
                tls_proxy_config.own_ip_address = LOCAL_STDIN_CLIENT_BRIDGE_IP;
                tls_proxy_config.listening_port = LOCAL_STDIN_CLIENT_BRIDGE_PORT;

                tls_proxy_config.target_ip_address = strtok(optarg, ":");

                char* port_str = strtok(NULL, ":");
                unsigned long dest_port = strtoul(port_str, NULL, 10);
                if ((dest_port == 0) || (dest_port > 65535))
                {
                    LOG_ERR("invalid port number %lu", dest_port);
                    exit(-1);
                }
                tls_proxy_config.target_port = (uint16_t) dest_port;

                role = ROLE_ECHO_CLIENT;
                break;
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
            case 's':
                tls_proxy_config.tls_config.use_secure_element = true;
                wolfssl_config.secure_element_middleware_path = optarg;
                break;
            case 'h': 
                printf("Usage: %s [OPTIONS]\n", argv[0]);
                printf("Options:\n");
                printf("  -e, --echo_server <port>          start a TLS echo server on given port\n");
                printf("  -f, --echo_client <ip:port>       start a TLS echo client with given server and forward all stdin data\n");
                printf("  -c, --cert <file_path>            path to the certificate file\n");
                printf("  -k, --key <file_path>             path to the private key file\n");
                printf("  -i, --intermediate <file_path>    path to an intermediate certificate file\n");
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
	ret = wolfssl_init(&wolfssl_config);
	if (ret != 0)
		fatal("unable to initialize WolfSSL");

	/* Run the proxy (asynchronously) */
	ret = tls_proxy_backend_run();
	if (ret != 0)
		fatal("unable to run tls proxy application");

    /* Read certificates */
    if (read_certificates(&certs) != 0)
        fatal("unable to read certificates");


    /* Set TLS config */
    tls_proxy_config.tls_config.device_certificate_chain.buffer = certs.cert_chain_buffer;
    tls_proxy_config.tls_config.device_certificate_chain.size = certs.cert_chain_buffer_size;
    tls_proxy_config.tls_config.private_key.buffer = certs.key_buffer;
    tls_proxy_config.tls_config.private_key.size = certs.key_buffer_size;
    tls_proxy_config.tls_config.root_certificate.buffer = certs.root_buffer;
    tls_proxy_config.tls_config.root_certificate.size = certs.root_buffer_size;

    int id = -1;

    if (role == ROLE_ECHO_SERVER)
    {
        /* Add the TCP echo server */
        ret = tcp_echo_server_run(&tcp_echo_server_config);
        if (ret != 0)
            fatal("unable to run TCP echo server");

        /* Add the new TLS reverse proxy to the application backend */
        id = tls_reverse_proxy_start(&tls_proxy_config);
        if (id < 0)
            fatal("unable to start TLS reverse proxy");
        
        LOG_INF("started TLS reverse proxy with id %d", id);
    }
    else if (role == ROLE_ECHO_CLIENT)
    {
        /* Add the new TLS forward proxy to the application backend */
        id = tls_forward_proxy_start(&tls_proxy_config);
        if (id < 0)
            fatal("unable to start TLS forward proxy");

        /* Add the TCP client stdin bridge */
        ret = tcp_client_stdin_bridge_run(&tcp_client_stdin_bridge_config);
        if (ret != 0)
            fatal("unable to run TCP client stdin bridge");
        
        LOG_INF("started TLS forward proxy with id %d", id);
    }
    else
    {
        fatal("no role specified");
    }


    while (running)
    {
        sleep(1);
    }

    printf("Terminating...\n");

    /* We only land here if we received a terminate signal. First, we
     * kill the running server (especially its running client thread, if
     * present). Then, we kill the actual application thread. */
    tls_proxy_stop(id);
    tls_proxy_backend_terminate();
    
    if (role == ROLE_ECHO_SERVER)
    {
        tcp_echo_server_terminate();
    }
    else if (role == ROLE_ECHO_CLIENT)
    {
        tcp_client_stdin_bridge_terminate();
    }

	return 0;
}
