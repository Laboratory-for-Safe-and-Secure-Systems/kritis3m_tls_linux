
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
#include "poll_set.h"

#include "tls_proxy.h"
#include "tcp_echo_server.h"
#include "tcp_client_stdin_bridge.h"

#include "cli_parsing.h"


LOG_MODULE_CREATE(kritis3m_proxy);


#define ANY_IP "0.0.0.0"

#define LOCALHOST_IP "127.0.0.1"


#define fatal(msg, ...) { \
		LOG_ERROR("Error: " msg "", ##__VA_ARGS__); \
		exit(-1); \
	}


volatile __sig_atomic_t running = true;

static void signal_handler(int signo)
{
        (void) signo;

        /* Indicate the main process to stop */
        running = false;
}


int main(int argc, char** argv)
{
        application_config app_config;
        proxy_backend_config tls_proxy_backend_config;
	proxy_config tls_proxy_config;

        /* Install the signal handler and ignore SIGPIPE */
        if (signal(SIGINT, signal_handler) == SIG_ERR)
                printf("\ncan't catch SIGINT\n");
        if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
                printf("\ncan't ignore SIGPIPE\n");


        /* Parse arguments */
        int ret = parse_cli_arguments(&app_config, &tls_proxy_backend_config,
                                      &tls_proxy_config, argc, argv);
        LOG_LVL_SET(app_config.log_level);
        if (ret < 0)
        {
                fatal("unable to parse command line arguments");
        }
        else if (ret > 0)
        {
                exit(0); /* help was printed, so we can exit here */
        }

	/* Run the proxy (asynchronously) */
	ret = tls_proxy_backend_run(&tls_proxy_backend_config);
	if (ret != 0)
		fatal("unable to run tls proxy application");

        int id = -1;

        if (app_config.role == ROLE_REVERSE_PROXY)
        {
                /* Add the new TLS reverse proxy to the application backend */
                id = tls_reverse_proxy_start(&tls_proxy_config);
                if (id < 0)
                        fatal("unable to start TLS reverse proxy");

                LOG_INFO("started TLS reverse proxy with id %d", id);
        }
        else if (app_config.role == ROLE_FORWARD_PROXY)
        {
                /* Add the new TLS forward proxy to the application backend */
                id = tls_forward_proxy_start(&tls_proxy_config);
                if (id < 0)
                        fatal("unable to start TLS forward proxy");

                LOG_INFO("started TLS forward proxy with id %d", id);
        }
        else if (app_config.role == ROLE_ECHO_SERVER)
        {
                 tcp_echo_server_config tcp_echo_server_config = {
                        .own_ip_address = LOCALHOST_IP,
                        .listening_port = 0, /* Select random available port */
                        .log_level = app_config.log_level,
                };

                /* Add the TCP echo server */
                ret = tcp_echo_server_run(&tcp_echo_server_config);
                if (ret != 0)
                        fatal("unable to run TCP echo server");

                /* Obtain the listening port of the TCP echo server */
                tcp_echo_server_status echo_server_status;
                if (tcp_echo_server_get_status(&echo_server_status) < 0)
                        fatal("unable to run TCP echo server");

                /* Configure the TLS reverse proxy */
                tls_proxy_config.target_ip_address = LOCALHOST_IP;
                tls_proxy_config.target_port = echo_server_status.listening_port;

                /* Add the new TLS reverse proxy to the application backend */
                id = tls_reverse_proxy_start(&tls_proxy_config);
                if (id < 0)
                        fatal("unable to start TLS reverse proxy");

                LOG_INFO("started TLS reverse proxy with id %d", id);
        }
        else if (app_config.role == ROLE_TLS_CLIENT)
        {
                tcp_client_stdin_bridge_config tcp_client_stdin_bridge_config = {
                        .target_ip_address = LOCALHOST_IP,
                        .target_port = 0, /* Updated to the random port of the forward proxy */
                        .log_level = app_config.log_level,
                };

                /* Configure the forward proxy */
                tls_proxy_config.own_ip_address = LOCALHOST_IP;
                tls_proxy_config.listening_port = 0; /* Select random available port */

                /* Add the new TLS forward proxy to the application backend */
                id = tls_forward_proxy_start(&tls_proxy_config);
                if (id < 0)
                        fatal("unable to start TLS forward proxy");

                /* Obtain the listing port of the forward proxy */
                proxy_status forward_proxy_status;
                if (tls_proxy_get_status(id, &forward_proxy_status) < 0)
                        fatal("unable to run TLS forward proxy");

                /* Add the TCP client stdin bridge */
                tcp_client_stdin_bridge_config.target_port = forward_proxy_status.incoming_port;
                ret = tcp_client_stdin_bridge_run(&tcp_client_stdin_bridge_config);
                if (ret != 0)
                        fatal("unable to run TCP client stdin bridge");

                LOG_INFO("started TLS client stdin bridge");
        }
        else
        {
                fatal("no role specified");
        }

        /* Free memory */
        if (tls_proxy_config.tls_config.device_certificate_chain.buffer != NULL)
                free((uint8_t*)tls_proxy_config.tls_config.device_certificate_chain.buffer);
        if (tls_proxy_config.tls_config.private_key.buffer != NULL)
                free((uint8_t*)tls_proxy_config.tls_config.private_key.buffer);
        if (tls_proxy_config.tls_config.private_key.additional_key_buffer != NULL)
                free((uint8_t*)tls_proxy_config.tls_config.private_key.additional_key_buffer);
        if (tls_proxy_config.tls_config.root_certificate.buffer != NULL)
                free((uint8_t*)tls_proxy_config.tls_config.root_certificate.buffer);

        while (running)
        {
                // proxy_status proxy_status;
                // if (tls_proxy_get_status(id, &proxy_status) < 0)
                //         fatal("unable to obtain proxy status");
                // LOG_INFO("proxy status: %d connections", proxy_status.num_connections);

                /* Check if the bridge was able to connect */
                if (app_config.role == ROLE_TLS_CLIENT)
                {
                        tcp_client_stdin_bridge_status bridge_status;
                        if ((tcp_client_stdin_bridge_get_status(&bridge_status) < 0) || !bridge_status.is_running)
                                break;
                }

                usleep(100 * 1000);
        }

        LOG_INFO("Terminating...");

        /* We only land here if we received a terminate signal. First, we
        * kill the running server (especially its running client thread, if
        * present). Then, we kill the actual application thread. */
        tls_proxy_stop(id);
        tls_proxy_backend_terminate();

        if (app_config.role == ROLE_ECHO_SERVER)
        {
                tcp_echo_server_terminate();
        }
        else if (app_config.role == ROLE_TLS_CLIENT)
        {
                tcp_client_stdin_bridge_terminate();
        }

	return 0;
}
