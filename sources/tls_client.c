// Simple TLS Client using WolfSSL
//
// Created by Tobias Frauenschläger at 21.04.2023
//

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


#include "oqs/oqsconfig.h"


#define READ_BUFFER_SIZE 8192

#define IP "192.168.0.10"
#define PORT 443


/* Handle a fatal error.
 * This can only happen in the initialization routine. */
void checkForError(int32_t ret)
{
    if (ret != WOLFSSL_SUCCESS)
    {
        char errMsg[WOLFSSL_MAX_ERROR_SZ];
        wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));
        printf("Error: %s\r\n", errMsg);
        exit(-1);
    }
}


int main(char** argv, int argc)
{
    /* Initialize WolfSSL */
    int ret = wolfssl_init();
    if (ret != 0)
    {
        printf("Error initializing WolfSSL\r\n");
        exit(-1);
    }

    /* Setup a new TLS client context */
    WOLFSSL_CTX* wolfssl_ctx = wolfssl_setup_client_context();

    /* Create a TCP socket */
    int tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_socket == -1)
    {
        printf("Error creating TCP socket\r\n");
        exit(-1);
    }

    /* Configure TCP remote peer */
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(IP);
    servaddr.sin_port = htons(PORT);

    /* Etablish the TCP connection */
    ret = connect(tcp_socket, (struct sockaddr*) &servaddr, sizeof(servaddr));
    if (ret != 0)
    {
        printf("Error connecting to the TCP host\r\n");
        exit(-1);
    }

    /* Create a new TLS session from the context */
    WOLFSSL* wolfssl_session = wolfSSL_new(wolfssl_ctx);

    if (wolfssl_session == NULL)
    {
        printf("Error creating the WolfSSL session\r\n");
        exit(-1);
    }

    wolfSSL_UseKeyShare(wolfssl_session, WOLFSSL_KYBER_LEVEL3);
    // wolfSSL_UseKeyShare(wolfssl_session, WOLFSSL_P384_KYBER_LEVEL3);

    wolfSSL_set_fd(wolfssl_session, tcp_socket);

    /* Perform handshake */
    ret = wolfssl_handshake(wolfssl_session);
    if (ret != 0)
    {
        printf("TLS handshake failed\r\n");
        exit(-1);
    }
    else
    {
        printf("Handshake done\r\n");
    }
    
    /* Test the echo server */
    char const* message = "Hello World from TLS\r\n";
    int message_len = strlen(message);
    ret = wolfssl_send(wolfssl_session, (uint8_t*) message, message_len);
    if (ret != 0)
    {
        printf("Error sending data to the peer\r\n");
        exit(-1);
    }

    char buf[256];
    ret = wolfssl_receive(wolfssl_session, buf, sizeof(buf));
    if (ret <= 0)
    {
        printf("Error receiving data from the peer\r\n");
        exit(-1);
    }

    if (ret == message_len && memcmp(message, buf, message_len) == 0)
    {
        printf("Echo works as intended\r\n");
    }
    else
    {
        printf("Received invalid data from the echo server\r\n");
    }

    wolfSSL_shutdown(wolfssl_session);

    close(tcp_socket); 

    return 0;
}