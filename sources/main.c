
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

#include "cli_parsing.h"


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


volatile __sig_atomic_t running = true;

static void signal_handler(int signo)
{
    /* Indicate the main process to stop */
    running = false;
}



int main(int argc, char** argv)
{
    enum application_role role;

    wolfssl_library_configuration wolfssl_config;

	struct proxy_config tls_proxy_config;

    struct tcp_echo_server_config tcp_echo_server_config = {
        .own_ip_address = LOCAL_ECHO_SERVER_IP,
        .listening_port = LOCAL_ECHO_SERVER_PORT,
    };

    struct tcp_client_stdin_bridge_config tcp_client_stdin_bridge_config = {
        .target_ip_address = LOCAL_STDIN_CLIENT_BRIDGE_IP,
        .target_port = LOCAL_STDIN_CLIENT_BRIDGE_PORT,
    };

    /* Install the signal handler */
    struct sigaction signal_action;
    sigemptyset(&signal_action.sa_mask);
    signal_action.sa_handler = signal_handler;
    sigaction(SIGINT, &signal_action, NULL);

    /* Parse arguments */
    int ret = parse_cli_arguments(&role, &tls_proxy_config, &wolfssl_config,
                                  &(struct shell){0}, argc, argv);
    if (ret < 0)
    {
        fatal("unable to parse command line arguments");
    }
    else if (ret > 0)
    {
        exit(0); /* help was printed, so we can exit here */
    }

    /* Initialize WolfSSL */
	ret = wolfssl_init(&wolfssl_config);
	if (ret != 0)
		fatal("unable to initialize WolfSSL");

	/* Run the proxy (asynchronously) */
	ret = tls_proxy_backend_run();
	if (ret != 0)
		fatal("unable to run tls proxy application");



    int id = -1;

    if (role == ROLE_REVERSE_PROXY)
    {
        /* Add the new TLS reverse proxy to the application backend */
        id = tls_reverse_proxy_start(&tls_proxy_config);
        if (id < 0)
            fatal("unable to start TLS reverse proxy");
        
        LOG_INF("started TLS reverse proxy with id %d", id);
    }
    else if (role == ROLE_FORWARD_PROXY)
    {
        /* Add the new TLS forward proxy to the application backend */
        id = tls_forward_proxy_start(&tls_proxy_config);
        if (id < 0)
            fatal("unable to start TLS forward proxy");
        
        LOG_INF("started TLS forward proxy with id %d", id);
    }
    else if (role == ROLE_ECHO_SERVER)
    {
        tls_proxy_config.target_ip_address = LOCAL_ECHO_SERVER_IP;
        tls_proxy_config.target_port = LOCAL_ECHO_SERVER_PORT;
        
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
        tls_proxy_config.own_ip_address = LOCAL_STDIN_CLIENT_BRIDGE_IP;
        tls_proxy_config.listening_port = LOCAL_STDIN_CLIENT_BRIDGE_PORT;

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
