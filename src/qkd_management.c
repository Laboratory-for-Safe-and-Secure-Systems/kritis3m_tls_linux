
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
#include "quest.h"

LOG_MODULE_CREATE(qkd_management);

/// @brief  allocates the qkd_key_info struct in the PSK Server Config (PSK_SRV_CONF).
/// @return returns pointer to the qkd_key_info object if allocation was successfull,
///         otherwise returns NULL.
struct qkd_key_info* kritis3m_allocate_key_info()
{
        struct qkd_key_info* key_info = malloc(sizeof(struct qkd_key_info));
        if (key_info == NULL)
        {
                LOG_ERROR("failed to allocate key_info struct.");
                return NULL;
        }

        /*initialize key_info struct object with zero */
        memset(key_info, 0, sizeof(struct qkd_key_info));

        return key_info;
}

/// @brief To get the remote_sae_ID on the server side, we need to deparse both the sae_ID and the
///        qkd_key identity from the identity string we receive from the qkd_client.
/// @param identity concatenation of the sae_id and the qkd_key identifier sent by the client.
/// @param dst_sae_ID reference to the destination sae_ID buffer.
static void parse_server_remote_sae_id(char** identity, char** dst_sae_ID)
{
        /* From the qkd_client we receive an identity with the following structure */
        /* <remote_sae_id> : <qkd_key_identifier> */

        /* assign start of the identity to the remote_sae_id */
        *dst_sae_ID = *identity;

        /* Strip the remote_sae_id from the key identifier */
        char* identity_start = strchr((*identity), ':');
        if (identity_start != NULL)
        {
                /* Terminate the identity string */
                *identity_start = '\0';

                /* Set reference to qkd_key identity */
                *identity = identity_start + 1;
        }
        else
        {
                LOG_ERROR("remote_sae_id was not part of the identifier.");
                *dst_sae_ID = NULL;
        }
}

/// @brief requests a new QKD key from the QKD line ether without or without a specific key_ID
///        parameter and copies the key and the identity to the key_info parameter.
/// @param ctx callback_context containing the asl_endoint, if a secure connection to the QKD
///            line is desired. Otherwise this parameter is NULL.
/// @param key_info struct object, which contains the reserved buffer for key and key_ID as
///                 well as the associated sizes.
/// @param identity (OPTIONAL) string of the key_ID sent by the client to the server to request
///                 the corresponding QKD key. In case the tls client is calling this function,
///                 identity is set to NULL.
/// @param dst_sae_ID Identifier of the destination Secure Application Entity, which should be
///                   referenced in the GET_KEY request.
/// @return returns the E_OK or a specific status return in case of an error.
enum kritis3m_status_info kritis3m_get_qkd_key(quest_endpoint* qkd_endpoint,
                                               struct qkd_key_info* key_info,
                                               char* identity,
                                               const char* dst_sae_ID)
{
        enum kritis3m_status_info status;
        quest_transaction* key_request;

        /* if identity is NULL, we are on the client side requesting a new key without an ID */
        if (identity == NULL)
        {
                key_request = quest_setup_transaction(qkd_endpoint,
                                                      HTTP_KEY_NO_ID,
                                                      (char*) dst_sae_ID,
                                                      NULL);
        }
        else /* if an identity is passed as a parameter, we request a key with a specific ID */
        {
                key_request = quest_setup_transaction(qkd_endpoint,
                                                      HTTP_KEY_WITH_ID,
                                                      (char*) dst_sae_ID,
                                                      identity);
        }

        if (key_request == NULL)
        {
                LOG_ERROR("allocation of quest transaction did not succeed.");
                return ALLOC_ERR;
        }

        status = quest_execute_transaction(key_request);
        if (status != E_OK)
        {
                LOG_ERROR("error occured during transaction execution.");
                goto TRANSACTION_ERR;
        }

        struct http_get_response* key_response = quest_get_transaction_response(key_request);
        if (key_request == NULL)
        {
                LOG_ERROR("error occured during key request.");
                goto TRANSACTION_ERR;
        }

        /* if identity is NULL, we can copy the key_ID and key to the key_info object */
        if (identity != NULL)
        {
                /* if not, we perform a sanity check to verify the correct QKD key */
                if (strcmp(key_response->key_info->key_ID, identity) != 0)
                {
                        LOG_ERROR("identities do not match!");
                        goto TRANSACTION_ERR;
                }
        }

        key_info->key_len = key_response->key_info->key_len;
        key_info->key_ID_len = key_response->key_info->key_ID_len;

        /* copy key from the http_response oject */
        memcpy(key_info->key, key_response->key_info->key, (key_info->key_len + 1));

        /* pass host_sae_id as preceding parameter seperated with a ':' */
        quest_get_own_sae_id(qkd_endpoint, key_info->key_ID);
        strcat(key_info->key_ID, ":");

        /* append key ID from the http_response object */
        strcat(key_info->key_ID, key_response->key_info->key_ID);

        /* adjust new key_ID length */
        key_info->key_ID_len = strlen(key_info->key_ID);

        /* if everything worked correctly we can close the transaction. */
        quest_close_transaction(key_request);
        quest_free_transaction(key_request);

        return E_OK;

TRANSACTION_ERR:
        quest_free_transaction(key_request);
        return E_NOT_OK;
}

unsigned int asl_psk_client_callback(char* key, char* identity, void* ctx)
{
        enum kritis3m_status_info status;
        struct qkd_key_info* key_info;

        /* parse quest_connection from callback context */
        quest_connection* qkd_connection = (quest_connection*) ctx;
        if (qkd_connection == NULL)
        {
                LOG_ERROR("callback context was NULL here.");
                return ALLOC_ERR;
        }

        key_info = kritis3m_allocate_key_info();
        if (key_info == NULL)
                return 0;

        status = kritis3m_get_qkd_key(qkd_connection->local_endpoint,
                                      key_info,
                                      NULL,
                                      qkd_connection->remote_sae_ID);
        if (status == E_OK)
        {
                memcpy(key, key_info->key, (key_info->key_len + 1));
                memcpy(identity, key_info->key_ID, (key_info->key_ID_len + 1));
        }

        free(key_info);
        return strlen(key);
}

unsigned int asl_psk_server_callback(char* key, char* identity, void* ctx)
{
        enum kritis3m_status_info status;
        struct qkd_key_info* key_info;

        /* parse quest_connection from callback context */
        quest_connection* qkd_connection = (quest_connection*) ctx;
        if (qkd_connection == NULL)
        {
                LOG_ERROR("callback context was NULL here.");
                return ALLOC_ERR;
        }

        char* dst_sae_ID;
        parse_server_remote_sae_id(&identity, &dst_sae_ID);

        key_info = kritis3m_allocate_key_info();
        if (key_info == NULL)
                return 0;

        status = kritis3m_get_qkd_key(qkd_connection->local_endpoint, key_info, identity, dst_sae_ID);
        if (status == E_OK)
        {
                memcpy(key, key_info->key, (key_info->key_len + 1));
        }

        free(key_info);
        return strlen(key);
}
