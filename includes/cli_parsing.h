#ifndef CLI_PARSING_H
#define CLI_PARSING_H

#include <stdint.h>
#include <stdlib.h>

#include "logging.h"
#include "asl.h"
#include "tls_proxy.h"


enum application_role
{
        NOT_SET,
        ROLE_REVERSE_PROXY,
        ROLE_FORWARD_PROXY,
        ROLE_ECHO_SERVER,
        ROLE_ECHO_CLIENT,
};


typedef struct application_config
{
        enum application_role role;
        int32_t log_level;
}
application_config;


/* Parse the provided argv array and store the information in the provided config variables.
 *
 * Returns 0 on success, +1 in case the help was printed and -1 on failure (error is printed on console).
 */
int parse_cli_arguments(application_config* app_config, asl_configuration* asl_config,
                        proxy_backend_config* proxy_backend_config, proxy_config* proxy_config,
                        size_t argc, char** argv);


#endif // CLI_PARSING_H
