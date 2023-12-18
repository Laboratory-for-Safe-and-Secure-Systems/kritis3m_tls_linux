#ifndef CERTIFICATE_HANDLING_H
#define CERTIFICATE_HANDLING_H

#include <stdint.h>
#include <stdlib.h>

struct certificates
{
        /* File paths */
        char* certificate_path;
        char* private_key_path;
        char* intermediate_path;
        char* root_path;

        /* Variables for the actual read data */
        uint8_t* cert_chain_buffer; /* Entity certificate and intermediate */
        size_t cert_chain_buffer_size;

        uint8_t* key_buffer;
        size_t key_buffer_size;
        
        uint8_t* root_buffer;
        size_t root_buffer_size;
};


/* Read all certificate and key files from the paths provided in the `certs` 
 * structure and store the data in the buffers. Memory is allocated internally
 * and must be freed by the user. 
 * 
 * Returns 0 on success, -1 on failure (error is printed on console). */
int read_certificates(struct certificates* certs);

#endif // CERTIFICATE_HANDLING_H
