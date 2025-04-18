
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "file_io.h"
#include "logging.h"
#include "networking.h"

#include "echo_server.h"
#include "http_service.h"
#include "kritis3m_scale_service.h"
#include "network_tester.h"
#include "quest.h"
#include "tcp_client_stdin_bridge.h"
#include "tls_proxy.h"

#include "cli_parsing.h"

LOG_MODULE_CREATE(kritis3m_tls);

#define fatal(...)                                                                                 \
        {                                                                                          \
                LOG_ERROR(__VA_ARGS__);                                                            \
                exit(1);                                                                           \
        }

volatile bool running = true;

static void signal_handler(int signum)
{
        (void) signum;

        /* Indicate the main process to stop */
        running = false;
}

int main(int argc, char** argv)
{
        application_config app_config = {0};
        proxy_backend_config tls_proxy_backend_config = tls_proxy_backend_default_config();
        proxy_config tls_proxy_config = tls_proxy_default_config();
        echo_server_config echo_server_config = echo_server_default_config();
        network_tester_config network_tester_config = network_tester_default_config();
        quest_configuration* quest_config = quest_default_config();
        quest_endpoint* qkd_endpoint = NULL;

        char* management_file_path = NULL;

        /* Install the signal handler and ignore SIGPIPE */
        if (signal(SIGINT, signal_handler) == SIG_ERR)
                fatal("can't catch SIGINT\n");
        if (signal(SIGTERM, signal_handler) == SIG_ERR)
                fatal("can't catch SIGTERM\n");
#ifndef _WIN32
        if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
                fatal("can't ignore SIGPIPE\n");
#endif

        /* Parse arguments */
        int ret = parse_cli_arguments(&app_config,
                                      &tls_proxy_backend_config,
                                      &tls_proxy_config,
                                      &echo_server_config,
                                      &network_tester_config,
                                      quest_config,
                                      &management_file_path,
                                      argc,
                                      argv);
        LOG_LVL_SET(app_config.log_level);
        if (ret < 0)
        {
                fatal("unable to parse command line arguments");
        }
        else if (ret > 0)
        {
                exit(0); /* help was printed, so we can exit here */
        }

        /* Make sure network related settings are set */
        initialize_network_interfaces(app_config.log_level);

        if (app_config.use_qkd)
        {
                /* Setup quest_endpoint based on the configuration above. */
                qkd_endpoint = quest_setup_endpoint(quest_config);
                if (qkd_endpoint == NULL)
                {
                        LOG_ERROR("allocation of quest endpoint did not succeed.");
                        return -1;
                }
        }

        int id = -1;

        if (app_config.role == ROLE_REVERSE_PROXY)
        {
                if (app_config.use_qkd)
                {
                        /* Set PSK callback context to the quest_endpoint */
                        tls_proxy_config.tls_config.psk.callback_ctx = qkd_endpoint;
                }

                /* Run the proxy backend */
                ret = tls_proxy_backend_run(&tls_proxy_backend_config);
                if (ret != 0)
                        fatal("unable to run tls proxy backend");

                /* Add the new TLS reverse proxy to the application backend */
                id = tls_reverse_proxy_start(&tls_proxy_config);
                if (id < 0)
                        fatal("unable to start TLS reverse proxy");

                LOG_INFO("started TLS reverse proxy with id %d", id);
        }
        else if (app_config.role == ROLE_FORWARD_PROXY)
        {
                if (app_config.use_qkd)
                {
                        /* Set PSK callback context to the quest_endpoint */
                        tls_proxy_config.tls_config.psk.callback_ctx = qkd_endpoint;
                }

                /* Run the proxy backend */
                ret = tls_proxy_backend_run(&tls_proxy_backend_config);
                if (ret != 0)
                        fatal("unable to run tls proxy backend");

                /* Add the new TLS forward proxy to the application backend */
                id = tls_forward_proxy_start(&tls_proxy_config);
                if (id < 0)
                        fatal("unable to start TLS forward proxy");

                LOG_INFO("started TLS forward proxy with id %d", id);
        }
        else if (app_config.role == ROLE_ECHO_SERVER)
        {
                if (app_config.use_qkd)
                {
                        /* Set PSK callback context to the quest_endpoint */
                        echo_server_config.tls_config.psk.callback_ctx = qkd_endpoint;
                }

                /* Run the TCP echo server */
                ret = echo_server_run(&echo_server_config);
                if (ret != 0)
                        fatal("unable to run TLS echo server");

                LOG_INFO("Started TLS echo server");
        }
        else if (app_config.role == ROLE_ECHO_SERVER_PROXY)
        {
                if (app_config.use_qkd)
                {
                        /* Set PSK callback context to the quest_endpoint */
                        tls_proxy_config.tls_config.psk.callback_ctx = qkd_endpoint;
                }

                /* Run the proxy backend */
                ret = tls_proxy_backend_run(&tls_proxy_backend_config);
                if (ret != 0)
                        fatal("unable to run tls proxy backend");

                /* Run the TCP echo server */
                ret = echo_server_run(&echo_server_config);
                if (ret != 0)
                        fatal("unable to run TCP echo server");

                /* Obtain the listening port of the TCP echo server */
                echo_server_status echo_server_status;
                if (echo_server_get_status(&echo_server_status) < 0)
                        fatal("unable to run TCP echo server");

                /* Configure the TLS reverse proxy */
                tls_proxy_config.target_port = echo_server_status.listening_port_v4;

                /* Add the new TLS reverse proxy to the application backend */
                id = tls_reverse_proxy_start(&tls_proxy_config);
                if (id < 0)
                        fatal("unable to start TLS reverse proxy");

                LOG_INFO("Started TLS echo server via a reverse proxy");
        }
        else if (app_config.role == ROLE_TLS_CLIENT)
        {
                if (app_config.use_qkd)
                {
                        /* Set PSK callback context to the quest_endpoint */
                        tls_proxy_config.tls_config.psk.callback_ctx = qkd_endpoint;
                }

                tcp_client_stdin_bridge_config tcp_client_stdin_bridge_config = {
                        .target_ip_address = LOCALHOST_IP,
                        .target_port = 0, /* Updated to the random port of the forward proxy */
                        .log_level = app_config.log_level,
                };

                /* Run the proxy backend */
                ret = tls_proxy_backend_run(&tls_proxy_backend_config);
                if (ret != 0)
                        fatal("unable to run tls proxy backend");

                /* Add the new TLS forward proxy to the application backend */
                id = tls_forward_proxy_start(&tls_proxy_config);
                if (id < 0)
                        fatal("unable to start TLS forward proxy");

                /* Obtain the listing port of the forward proxy */
                proxy_status forward_proxy_status;
                if (tls_proxy_get_status(id, &forward_proxy_status) < 0)
                        fatal("unable to run TLS forward proxy");

                /* Add the TCP client stdin bridge */
                tcp_client_stdin_bridge_config.target_port = forward_proxy_status.incoming_port_v4;
                ret = tcp_client_stdin_bridge_run(&tcp_client_stdin_bridge_config);
                if (ret != 0)
                        fatal("unable to run TCP client stdin bridge");

                LOG_INFO("started TLS client stdin bridge");
        }
        else if (app_config.role == ROLE_NETWORK_TESTER)
        {
                if (app_config.use_qkd)
                {
                        /* Set PSK callback context to the quest_endpoint */
                        network_tester_config.tls_config.psk.callback_ctx = qkd_endpoint;
                }

                /* Run the network_tester application asynchronously */
                ret = network_tester_run(&network_tester_config);
                if (ret != 0)
                        fatal("unable to run network tester");
        }
        else if (app_config.role == ROLE_NETWORK_TESTER_PROXY)
        {
                if (app_config.use_qkd)
                {
                        /* Set PSK callback context to the quest_endpoint */
                        tls_proxy_config.tls_config.psk.callback_ctx = qkd_endpoint;
                }

                /* Run the proxy backend */
                ret = tls_proxy_backend_run(&tls_proxy_backend_config);
                if (ret != 0)
                        fatal("unable to run tls proxy backend");

                /* Start the forward proxy */
                id = tls_forward_proxy_start(&tls_proxy_config);
                if (id < 0)
                        fatal("unable to start forward proxy");

                /* Obtain the listing port of the forward proxy */
                proxy_status forward_proxy_status;
                if (tls_proxy_get_status(id, &forward_proxy_status) < 0)
                        fatal("unable to run TLS forward proxy");

                /* Update the tester config */
                network_tester_config.target_port = forward_proxy_status.incoming_port_v4;

                /* Run the network_tester application asynchronously */
                ret = network_tester_run(&network_tester_config);
                if (ret != 0)
                        fatal("unable to run network tester");
        }
        else if ((app_config.role == ROLE_MANAGEMENT_CLIENT) || (management_file_path != NULL))
        {
                ret = start_kritis3m_service(management_file_path, app_config.log_level);
                if (ret < 0)
                {
                        return -1;
                }
        }
        else
        {
                fatal("no role specified");
        }

        /* Free memory */
        arguments_cleanup(&app_config,
                          &tls_proxy_backend_config,
                          &tls_proxy_config,
                          &echo_server_config,
                          &management_file_path,
                          &network_tester_config,
                          quest_config);

        ret = 0;
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
                        if ((tcp_client_stdin_bridge_get_status(&bridge_status) < 0) ||
                            !bridge_status.is_running)
                        {
                                ret = 1;
                                break;
                        }
                }
                else if ((app_config.role == ROLE_NETWORK_TESTER) ||
                         (app_config.role == ROLE_NETWORK_TESTER_PROXY))
                {
                        network_tester_status tester_status;
                        if ((network_tester_get_status(&tester_status) < 0) || !tester_status.is_running)
                        {
                                ret = tester_status.return_code;
                                break;
                        }
                }
                usleep(100 * 1000);
        }

        LOG_INFO("Terminating...");

        /* We only land here if we received a terminate signal. First, we
         * kill the running server (especially its running client thread, if
         * present). Then, we kill the actual application thread. */
        if (id != -1)
        {
                tls_proxy_stop(id);
                tls_proxy_backend_terminate();
        }

        if (qkd_endpoint != NULL)
        {
                quest_free_endpoint(qkd_endpoint);
        }

        if ((app_config.role == ROLE_ECHO_SERVER) || (app_config.role == ROLE_ECHO_SERVER_PROXY))
        {
                echo_server_terminate();
        }
        else if (app_config.role == ROLE_TLS_CLIENT)
        {
                tcp_client_stdin_bridge_terminate();
        }
        else if ((app_config.role == ROLE_NETWORK_TESTER) ||
                 (app_config.role == ROLE_NETWORK_TESTER_PROXY))
        {
                network_tester_terminate();
        }
        else if ((app_config.role == ROLE_MANAGEMENT_CLIENT) || (management_file_path != NULL))
        {
                LOG_INFO("stoping kritis3m_service");
                stop_kritis3m_service();
        }

        return ret;
}
