#ifndef CLI_PARSING_H
#define CLI_PARSING_H

#include <stdint.h>
#include <stdlib.h>

#include "asl.h"
#include "echo_server.h"
#include "logging.h"
#include "network_tester.h"
#include "quest.h"
#include "tls_proxy.h"

#define LOCALHOST_IP "127.0.0.1"

#define QKD_PSK_IDENTIFIER "qkd"
#define QKD_PSK_IDENTIFIER_LEN 3
#define SECURE_QKD_PSK_IDENTIFIER "qkd:secure"
#define SECURE_QKD_PSK_IDENTIFIER_LEN 10

enum application_role
{
        NOT_SET,
        ROLE_REVERSE_PROXY,
        ROLE_FORWARD_PROXY,
        ROLE_ECHO_SERVER,
        ROLE_ECHO_SERVER_PROXY,
        ROLE_TLS_CLIENT,
        ROLE_NETWORK_TESTER,
        ROLE_NETWORK_TESTER_PROXY,
        ROLE_MANAGEMENT_CLIENT,
};

typedef struct application_config
{
        enum application_role role;
        int32_t log_level;
        bool use_qkd;
} application_config;

/* Parse the provided argv array and store the information in the provided config variables.
 *
 * Returns 0 on success, +1 in case the help was printed and -1 on failure (error is printed on console).
 */
int parse_cli_arguments(application_config* app_config,
                        proxy_backend_config* proxy_backend_config,
                        proxy_config* proxy_config,
                        echo_server_config* echo_server_config,
                        network_tester_config* tester_config,
                        quest_configuration* quest_config,
                        char** management_file_path,
                        size_t argc,
                        char** argv);

/* Cleanup any structures created during argument parsing */
void arguments_cleanup(application_config* app_config,
                       proxy_backend_config* proxy_backend_config,
                       proxy_config* proxy_config,
                       echo_server_config* echo_server_config,
                       char** management_file_path,
                       network_tester_config* tester_config,
                       quest_configuration* quest_config);

/* Helper method to dynamically duplicate a string */
char* duplicate_string(char const* source);

#endif // CLI_PARSING_H
