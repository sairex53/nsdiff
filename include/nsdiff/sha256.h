#ifndef NSDIFF_SHA256_H
#define NSDIFF_SHA256_H
#include <stdint.h>
#include <stddef.h>
#define NSDIFF_SNAPSHOT_SHA256_LEN 32U
struct nsdiff_sha256_context {
    uint32_t state[8];
    uint64_t total_bytes;
    unsigned char block[64];
    size_t block_used;
};


void nsdiff_sha256_init(struct nsdiff_sha256_context *context);
void nsdiff_sha256_update(struct nsdiff_sha256_context *context, const void *data, size_t size);
void nsdiff_sha256_final(struct nsdiff_sha256_context *context, unsigned char digest[32]);
void nsdiff_sha256(const void *data, size_t size, unsigned char digest[32]);
#endif
