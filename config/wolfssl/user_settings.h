#ifndef _USER_SETTINGS_H_
#define _USER_SETTINGS_H_

#ifdef __cplusplus
extern "C" {
#endif

// Disable unused features
#define NO_SHA
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_DSA
#define NO_DH
#define NO_RC4
#define NO_PWDBASED
#define NO_RABBIT
#define NO_HC128
// #define NO_SESSION_CACHE
#define NO_RESUME_SUITE_CHECK
#define NO_WRITEV
// #define NO_FILESYSTEM
#define NO_DEV_URANDOM
#define NO_MULTIBYTE_PRINT
#define NO_OLD_TLS
// #define WOLFSSL_NO_TLS12
#define NO_OLD_RNGNAME
#define NO_AES_192

// Enable features 
#define WOLFSSL_USER_IO
#define HAVE_ECC384 
// #define WOLF_CRYPTO_CB 
// #define WOLF_CRYPTO_DEV 
#define WOLFSSL_NO_SOCK 
#define WOLFSSL_KEY_GEN 
#define WOLFSSL_ALWAYS_VERIFY_CB 
#define HAVE_CRL_IO 
#define HAVE_AESGCM
#define WOLFSSL_TLS13
#define HAVE_HKDF
#define HAVE_FFDHE_4096
#define WC_RSA_PSS
#define WC_RSA_BLINDING
#define WOLFSSL_RIPEMD
#define WOLFSSL_SNIFFER
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_TLS_EXTENSIONS
#define HAVE_ECC
#define ECC_SHAMIR
#define ECC_TIMING_RESISTANT
#define HAVE_SESSION_TICKET

#define HAVE_LIBOQS


/* Memory configuaration */
// #define WOLFSSL_STATIC_MEMORY
// #define WOLFSSL_SMALL_STACK


/* Math configuration */
#define WOLFSSL_SP_MATH
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_HAVE_SP_DH
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_SP_4096
#define WOLFSSL_SP_384
#define WOLFSSL_SP_521
#define WOLFSSL_SP_ASM
#define WOLFSSL_SP_X86_64
#define WOLFSSL_SP_X86_64_ASM


#ifdef __cplusplus
}
#endif

#endif /* _USER_SETTINGS_H_ */
