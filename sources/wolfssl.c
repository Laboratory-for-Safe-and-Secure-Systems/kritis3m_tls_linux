
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "wolfssl.h"

#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/memory.h"
#include "wolfssl/error-ssl.h"


#ifdef WOLFSSL_STATIC_MEMORY
static WOLFSSL_HEAP_HINT* wolfssl_heap;
#else
#define wolfssl_heap NULL
#endif


#define ROOT_CERT "/home/tobi/workspace/certificates/dilithium/dilithium_level3_root_cert.pem"
#define DEVICE_CERT "/home/tobi/workspace/certificates/dilithium/dilithium_level3_entity_cert.pem"
#define DEVICE_KEY "/home/tobi/workspace/certificates/dilithium/dilithium_level3_entity_key.pem"


/* Check return value for an error. Print error message in case. */
static int errorOccured(int32_t ret)
{
	if (ret != WOLFSSL_SUCCESS)
	{
		char errMsg[WOLFSSL_MAX_ERROR_SZ];
		wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));
		printf("WolfSSL error: %s", errMsg);

		return -1;
	}

	return 0;
}

static int wolfssl_read_callback(WOLFSSL* session, char* buffer, int size, void* ctx)
{
	(void) ctx;

	int socket = wolfSSL_get_fd(session);

	int ret = recv(socket, buffer, size, 0);

	if (ret == 0)
	{
		return WOLFSSL_CBIO_ERR_CONN_CLOSE;
	}
	else if (ret < 0)
	{
		return WOLFSSL_CBIO_ERR_GENERAL;
	}
	
	return ret;
}

static int wolfssl_write_callback(WOLFSSL* session, char* buffer, int size, void* ctx)
{
	(void) ctx;

	int socket = wolfSSL_get_fd(session);

	return send(socket, buffer, size, 0);
}

static void wolfssl_logging_callback(int level, const char* str)
{
	(void) level;

	printf("%s\r\n", str);
}


/* Initialize WolfSSL library.
 *
 * Returns 0 on success, -1 in case of an error (error message is logged to the console).
 */
int wolfssl_init(void)
{
        /* Initialize WolfSSL */
	int ret = wolfSSL_Init();
	if (errorOccured(ret))
		return -1; 

        #ifdef WOLFSSL_STATIC_MEMORY
	/* Load static memory to avoid malloc */
	if (wc_LoadStaticMemory(&wolfssl_heap, wolfsslMemoryBuffer, sizeof(wolfsslMemoryBuffer), WOLFMEM_GENERAL, 1) != 0) {
		fatal("unable to load static memory");
	}
        #endif

	/* Configure the logging interface */
    	// ret = wolfSSL_SetLoggingCb(wolfssl_logging_callback);
    	// wolfSSL_Debugging_ON();

        return 0;
}


/* Configure the new context.
 * 
 * Returns 0 on success, -1 on failure (error message is logged to the console).
 */
static int wolfssl_configure_context(WOLFSSL_CTX* context)
{
        /* Only allow TLS version 1.3 */
	int ret = wolfSSL_CTX_SetMinVersion(context, WOLFSSL_TLSV1_3);
	if (errorOccured(ret))
		return -1;

	/* Load root certificate */
	ret = wolfSSL_CTX_load_verify_locations(context, 
						ROOT_CERT,
                                                NULL);
	if (errorOccured(ret))
		return -1;

	/* Load device and intermediate certs */
	ret = wolfSSL_CTX_use_certificate_chain_file_format(context,
							    DEVICE_CERT,
							    WOLFSSL_FILETYPE_PEM);
	if (errorOccured(ret))
		return -1;

	/* Load the private key */
	ret = wolfSSL_CTX_use_PrivateKey_file(context,
					      DEVICE_KEY,
                                              WOLFSSL_FILETYPE_PEM);
	if (errorOccured(ret))
		return -1; 


	/* Check if the private key and the device certificate match */
	ret = wolfSSL_CTX_check_private_key(context);
	if (errorOccured(ret))
		return -1;

	/* Configure the available cipher suites for TLS 1.3;
	* We only support AES GCM with 256 bit key length */
	ret = wolfSSL_CTX_set_cipher_list(context, "TLS13-AES256-GCM-SHA384");
	if (errorOccured(ret))
		return -1;

	/* Set the IO callbacks for send and receive */
	wolfSSL_CTX_SetIORecv(context, wolfssl_read_callback);
	wolfSSL_CTX_SetIOSend(context, wolfssl_write_callback);

	/* Set peer authentification to required */
	wolfSSL_CTX_set_verify(context, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	return 0;
}


/* Setup a TLS server context.
 *
 * Return value is a pointer to the newly created context or NULl in case of an error
 * (error message is logged to the console).
 */
WOLFSSL_CTX* wolfssl_setup_server_context(void)
{
        /* Create the TLS server context */
	WOLFSSL_CTX* new_context = wolfSSL_CTX_new_ex(wolfTLS_server_method_ex(wolfssl_heap), wolfssl_heap);
	if (new_context == NULL)
	{
		printf("Unable to create a new WolfSSL server context");
		return NULL;
	}

	/* Configure the new context */
        int ret = wolfssl_configure_context(new_context);
        if (ret == -1)
        {
                printf("Failed to configure new TLS server context\r\n");
                wolfSSL_CTX_free(new_context);
	        return NULL;
        }

        return new_context;
}


/* Setup a TLS client context.
 *
 * Return value is a pointer to the newly created context or NULl in case of an error
 * (error message is logged to the console).
 */
WOLFSSL_CTX* wolfssl_setup_client_context(void)
{
        /* Create the TLS client context */
	WOLFSSL_CTX* new_context = wolfSSL_CTX_new_ex(wolfTLS_client_method_ex(wolfssl_heap), wolfssl_heap);
	if (new_context == NULL)
	{
		printf("Unable to create a new WolfSSL client context");
		return NULL;
	}

	/* Configure the new context */
        int ret = wolfssl_configure_context(new_context);
        if (ret == -1)
        {
                printf("Failed to confiugre new TLS client context\r\n");
                wolfSSL_CTX_free(new_context);
	        return NULL;
        }

        return new_context;
}


/* Perform the TLS handshake for a newly created session.
 *
 * Returns 0 on success, -1 on failure (error message is logged to the console).
 */
int wolfssl_handshake(WOLFSSL* session)
{
        int ret = 0;
	while (ret != WOLFSSL_SUCCESS)
	{
		ret = wolfSSL_negotiate(session);

		if (ret == WOLFSSL_SUCCESS)
		{
			ret = 0;
			break;
		}
		else
		{
			ret = wolfSSL_get_error(session, ret);

			if ((ret == WOLFSSL_ERROR_WANT_READ) || (ret == WOLFSSL_ERROR_WANT_WRITE))
			{
				ret = 0;
				continue;
			}
			else
			{
				char errMsg[WOLFSSL_MAX_ERROR_SZ];
				wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));

				printf("TLS handshake failed: %s", errMsg);
				ret = -1;
				break;				
			}
		}
	}

	return ret;
}


/* Receive new data from the TLS peer (blocking read).
 *
 * Returns the number of received bytes on success, -1 on failure (error message is logged
 * to the console).
 */
int wolfssl_receive(WOLFSSL* session, uint8_t* buffer, int max_size)
{
        int ret = 0;
	
	while (1)
	{
		ret = wolfSSL_read(session, buffer, max_size);

		if (ret <= 0) 
		{
			ret = wolfSSL_get_error(session, ret);

			if ((ret == WOLFSSL_ERROR_WANT_READ) || (ret == WOLFSSL_ERROR_WANT_WRITE))
			{
				continue;
			}
			else if ((ret == WOLFSSL_ERROR_ZERO_RETURN) || (ret == SOCKET_PEER_CLOSED_E))
			{
				printf("TLS connection was closed gracefully");
				ret = -1;
				break;
			}
			else
			{
				char errMsg[WOLFSSL_MAX_ERROR_SZ];
				wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));

				printf("wolfSSL_read returned %d: %s", ret, errMsg);
				ret = -1;
				break;
			}
		}

		break;
	}

	return ret;
}


/* Send data to the TLS remote peer.
 *
 * Returns 0 on success, -1 on failure (error message is logged to the console).
 */
int wolfssl_send(WOLFSSL* session, uint8_t* buffer, int size)
{
        uint8_t* tmp = buffer;
	int ret = 0;

	while (size > 0)
	{
		ret = wolfSSL_write(session, tmp, size);

		if (ret > 0)
		{
			/* We successfully sent data */
			size -= ret;
			tmp += ret;
			ret = 0;
		}
		else
		{
			ret = wolfSSL_get_error(session, ret);

            		if (ret == WOLFSSL_ERROR_WANT_READ)
			{
				/* We have to first receive data from the peer. In this case,
				 * we discard the data and continue reading data from it. */
				ret = 0;
				break;
			}
			else if (ret == WOLFSSL_ERROR_WANT_WRITE)
			{
				/* We have more to write. */
				continue;
			}
			else
			{
				if (ret != 0)
				{
					char errMsg[WOLFSSL_MAX_ERROR_SZ];
					wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));

					printf("wolfSSL_write returned %d: %s", ret, errMsg);
				}
				ret = -1;

				break;
			}
		}

	}

	return ret;
}
