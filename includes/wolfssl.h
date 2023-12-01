#ifndef WOLFSSL_H
#define WOLFSSL_H

#include <stdint.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"  


/* Initialize WolfSSL library.
 *
 * Returns 0 on success, -1 in case of an error (error message is logged to the console).
 */
int wolfssl_init(void);


/* Setup a TLS server context.
 *
 * Return value is a pointer to the newly created context or NULl in case of an error
 * (error message is logged to the console).
 */
WOLFSSL_CTX* wolfssl_setup_server_context(void);


/* Setup a TLS client context.
 *
 * Return value is a pointer to the newly created context or NULl in case of an error
 * (error message is logged to the console).
 */
WOLFSSL_CTX* wolfssl_setup_client_context(void);


/* Perform the TLS handshake for a newly created session.
 *
 * Returns 0 on success, -1 on failure (error message is logged to the console).
 */
int wolfssl_handshake(WOLFSSL* session);


/* Receive new data from the TLS peer (blocking read).
 *
 * Returns the number of received bytes on success, -1 on failure (error message is logged
 * to the console).
 */
int wolfssl_receive(WOLFSSL* session, uint8_t* buffer, int max_size);


/* Send data to the TLS remote peer.
 *
 * Returns 0 on success, -1 on failure (error message is logged to the console).
 */
int wolfssl_send(WOLFSSL* session, uint8_t* buffer, int size);


#endif
