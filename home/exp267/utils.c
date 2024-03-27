#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

#include <errno.h>

int rand_bytes(uint8_t* dest, size_t destlen) {
    WC_RNG rng;
    int rv;

    rv = wc_InitRng(&rng);
    if (rv != 0) {
        fprintf(stderr, "Failed to initialise RNG\n");
        return -1;
    }

    rv = wc_RNG_GenerateBlock(&rng, dest, destlen);
    if (rv != 0) {
        fprintf(stderr, "Failed to generate random numbers\n");
        return -1;
    }

    rv = wc_FreeRng(&rng);
    if (rv != 0) {
        fprintf(stderr, "Failed to deallocate RNG memory\n");
        return -1;
    }

    return 0;
}

void rand_cb(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* rand_ctx) {
    rand_bytes(dest, destlen);
}

int get_new_connection_id_cb(ngtcp2_conn* conn, ngtcp2_cid* cid, uint8_t* token, size_t cidlen, void* user_data){
    // TODO - Consider implementing lookup and rehash. https://nghttp2.org/ngtcp2/ngtcp2_conn_get_scid.html
    WC_RNG rng;
    int rv;

    fprintf(stdout, "Starting call to get_new_connection_id_cb\n");

    rv = wc_InitRng(&rng);
    if (rv != 0) {
        fprintf(stderr, "Failed to initialise RNG\n");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    rv = wc_RNG_GenerateBlock(&rng, cid->data, cidlen);
    if (rv != 0) {
        fprintf(stderr, "Failed to generate random numbers\n");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    cid->datalen = cidlen;

    rv = wc_RNG_GenerateBlock(&rng, token, NGTCP2_STATELESS_RESET_TOKENLEN);
    if (rv != 0) {
        fprintf(stderr, "Failed to generate random numbers\n");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    rv = wc_FreeRng(&rng);
    if (rv != 0) {
        fprintf(stderr, "Failed to deallocate RNG memory\n");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

// Code taken from ngtcp2/examples/simpleclient.c
uint64_t timestamp(void) {
  struct timespec tp;

  if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
    fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

void debug_log(void *user_data, const char *format, ...) {
    va_list args;
    va_start(args, format);

    vfprintf(stdout, format, args);
    va_end(args);
    fprintf(stdout, "\n");
}
