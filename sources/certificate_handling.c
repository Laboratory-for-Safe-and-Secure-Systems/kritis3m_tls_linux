#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "logging.h"

#include "certificate_handling.h"


LOG_MODULE_REGISTER(certificate_handling);


static const size_t certificate_chain_buffer_size = 32 * 1024;
static const size_t private_key_buffer_size = 16 * 1024;
static const size_t root_certificate_buffer_size = 16 * 1024;


int readFile(const char* filePath, uint8_t* buffer, size_t bufferSize)
{
    /* Open the file */
    FILE* file = fopen(filePath, "r");
    
    if (file == NULL)
    {
        LOG_ERR("file (%s) cannot be opened", filePath);
        return -1;
    }
    
    /* Get length of file */
    fseek(file, 0, SEEK_END);
    int fileSize = ftell(file);
    rewind(file);

    if (fileSize > bufferSize)
    {
        LOG_ERR("file (%s) is too large for internal buffer", filePath);
        fclose(file);
        return -1;
    }
    
    /* Read file to buffer */
    int bytesRead = 0;
    while (bytesRead < fileSize)
    {
        int read = fread(buffer + bytesRead, sizeof(uint8_t), fileSize - bytesRead, file);
        if (read < 0)
        {
            LOG_ERR("unable to read file (%s)", filePath);
            fclose(file);
            return -1;
        }
        bytesRead += read;
    }
    
    fclose(file);

    return bytesRead;
}


/* Read all certificate and key files from the paths provided in the `certs` 
 * structure and store the data in the buffers. Memory is allocated internally
 * and must be freed by the user. 
 * 
 * Returns 0 on success, -1 on failure (error is printed on console). */
int read_certificates(struct certificates* certs)
{
        /* Allocate memory for the files to read */
        certs->cert_chain_buffer = (uint8_t*) malloc(certificate_chain_buffer_size);
        if (certs->cert_chain_buffer == NULL)
        {
                LOG_ERR("unable to allocate memory for certificate chain");
                goto error;
        }

        certs->key_buffer = (uint8_t*) malloc(private_key_buffer_size);
        if (certs->key_buffer == NULL)
        {
                LOG_ERR("unable to allocate memory for private key");
                goto error;
        }

        certs->root_buffer = (uint8_t*) malloc(root_certificate_buffer_size);
        if (certs->root_buffer == NULL)
        {
                LOG_ERR("unable to allocate memory for root certificate");
                goto error;
        }

        /* Read certificate chain */
        if (certs->certificate_path != NULL)
        {
                int cert_size = readFile(certs->certificate_path,
                                         certs->cert_chain_buffer,
                                         certificate_chain_buffer_size);
                if (cert_size < 0)
                {
                        LOG_ERR("unable to read certificate from file %s", certs->certificate_path);
                        goto error;
                }

                certs->cert_chain_buffer_size = cert_size;

                if (certs->intermediate_path != NULL)
                {
                        int inter_size = readFile(certs->intermediate_path,
                                                  certs->cert_chain_buffer + cert_size,
                                                  certificate_chain_buffer_size - cert_size);
                        if (inter_size < 0)
                        {
                                LOG_ERR("unable to read intermediate certificate from file %s", certs->intermediate_path);
                                goto error;
                        }

                        certs->cert_chain_buffer_size += inter_size;
                }
        }
        else
        {
                LOG_ERR("no certificate file specified");
                goto error;
        }

        /* Read private key */
        if (certs->private_key_path != 0)
        {
                int key_size = readFile(certs->private_key_path,
                                        certs->key_buffer,
                                        private_key_buffer_size);
                if (key_size < 0)
                {
                        LOG_ERR("unable to read private key from file %s", certs->private_key_path);
                        goto error;
                }

                certs->key_buffer_size = key_size;
        }
        else
        {
                LOG_ERR("no private key file specified");
                goto error;
        }

        /* Read root certificate */
        if (certs->root_path != 0)
        {
                int root_size = readFile(certs->root_path,
                                        certs->root_buffer,
                                        root_certificate_buffer_size);
                if (root_size < 0)
                {
                        LOG_ERR("unable to read root certificate from file %s", certs->root_path);
                        goto error;
                }

                certs->root_buffer_size = root_size;
        }
        else
        {
                LOG_ERR("no root certificate file specified");
                goto error;
        }

        return 0;

error:
        free(certs->cert_chain_buffer);
        free(certs->key_buffer);
        free(certs->root_buffer);

        return -1;
}