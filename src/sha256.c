#include <stdint.h>
#include <string.h>
#include "nsdiff/sha256.h"
static uint32_t sha256_rotr(
    uint32_t value,
    unsigned int shift
)
{
    return (value >> shift) |
           (value << (32U - shift));
}


static uint32_t sha256_load_be32(
    const unsigned char *p
)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}


static void sha256_store_be32(
    unsigned char *p,
    uint32_t value
)
{
    p[0] =
        (unsigned char)(value >> 24);

    p[1] =
        (unsigned char)(value >> 16);

    p[2] =
        (unsigned char)(value >> 8);

    p[3] =
        (unsigned char)value;
}


static void sha256_transform(
    struct nsdiff_sha256_context *context,
    const unsigned char block[64]
)
{
    static const uint32_t k[64] = {
        UINT32_C(0x428a2f98), UINT32_C(0x71374491),
        UINT32_C(0xb5c0fbcf), UINT32_C(0xe9b5dba5),
        UINT32_C(0x3956c25b), UINT32_C(0x59f111f1),
        UINT32_C(0x923f82a4), UINT32_C(0xab1c5ed5),
        UINT32_C(0xd807aa98), UINT32_C(0x12835b01),
        UINT32_C(0x243185be), UINT32_C(0x550c7dc3),
        UINT32_C(0x72be5d74), UINT32_C(0x80deb1fe),
        UINT32_C(0x9bdc06a7), UINT32_C(0xc19bf174),
        UINT32_C(0xe49b69c1), UINT32_C(0xefbe4786),
        UINT32_C(0x0fc19dc6), UINT32_C(0x240ca1cc),
        UINT32_C(0x2de92c6f), UINT32_C(0x4a7484aa),
        UINT32_C(0x5cb0a9dc), UINT32_C(0x76f988da),
        UINT32_C(0x983e5152), UINT32_C(0xa831c66d),
        UINT32_C(0xb00327c8), UINT32_C(0xbf597fc7),
        UINT32_C(0xc6e00bf3), UINT32_C(0xd5a79147),
        UINT32_C(0x06ca6351), UINT32_C(0x14292967),
        UINT32_C(0x27b70a85), UINT32_C(0x2e1b2138),
        UINT32_C(0x4d2c6dfc), UINT32_C(0x53380d13),
        UINT32_C(0x650a7354), UINT32_C(0x766a0abb),
        UINT32_C(0x81c2c92e), UINT32_C(0x92722c85),
        UINT32_C(0xa2bfe8a1), UINT32_C(0xa81a664b),
        UINT32_C(0xc24b8b70), UINT32_C(0xc76c51a3),
        UINT32_C(0xd192e819), UINT32_C(0xd6990624),
        UINT32_C(0xf40e3585), UINT32_C(0x106aa070),
        UINT32_C(0x19a4c116), UINT32_C(0x1e376c08),
        UINT32_C(0x2748774c), UINT32_C(0x34b0bcb5),
        UINT32_C(0x391c0cb3), UINT32_C(0x4ed8aa4a),
        UINT32_C(0x5b9cca4f), UINT32_C(0x682e6ff3),
        UINT32_C(0x748f82ee), UINT32_C(0x78a5636f),
        UINT32_C(0x84c87814), UINT32_C(0x8cc70208),
        UINT32_C(0x90befffa), UINT32_C(0xa4506ceb),
        UINT32_C(0xbef9a3f7), UINT32_C(0xc67178f2),
    };

    uint32_t w[64];

    uint32_t a;
    uint32_t b;
    uint32_t c_value;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;

    size_t i;

    for (i = 0;
         i < 16U;
         i++) {

        w[i] =
            sha256_load_be32(
                block + i * 4U
            );
    }

    for (i = 16U;
         i < 64U;
         i++) {

        uint32_t s0 =
            sha256_rotr(w[i - 15U], 7U) ^
            sha256_rotr(w[i - 15U], 18U) ^
            (w[i - 15U] >> 3U);

        uint32_t s1 =
            sha256_rotr(w[i - 2U], 17U) ^
            sha256_rotr(w[i - 2U], 19U) ^
            (w[i - 2U] >> 10U);

        w[i] =
            w[i - 16U] +
            s0 +
            w[i - 7U] +
            s1;
    }

    a = context->state[0];
    b = context->state[1];
    c_value = context->state[2];
    d = context->state[3];
    e = context->state[4];
    f = context->state[5];
    g = context->state[6];
    h = context->state[7];

    for (i = 0;
         i < 64U;
         i++) {

        uint32_t s1 =
            sha256_rotr(e, 6U) ^
            sha256_rotr(e, 11U) ^
            sha256_rotr(e, 25U);

        uint32_t choose =
            (e & f) ^
            ((~e) & g);

        uint32_t temp1 =
            h +
            s1 +
            choose +
            k[i] +
            w[i];

        uint32_t s0 =
            sha256_rotr(a, 2U) ^
            sha256_rotr(a, 13U) ^
            sha256_rotr(a, 22U);

        uint32_t majority =
            (a & b) ^
            (a & c_value) ^
            (b & c_value);

        uint32_t temp2 =
            s0 +
            majority;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c_value;
        c_value = b;
        b = a;
        a = temp1 + temp2;
    }

    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c_value;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
}


void nsdiff_sha256_init(
    struct nsdiff_sha256_context *context
)
{
    memset(
        context,
        0,
        sizeof(*context)
    );

    context->state[0] =
        UINT32_C(0x6a09e667);

    context->state[1] =
        UINT32_C(0xbb67ae85);

    context->state[2] =
        UINT32_C(0x3c6ef372);

    context->state[3] =
        UINT32_C(0xa54ff53a);

    context->state[4] =
        UINT32_C(0x510e527f);

    context->state[5] =
        UINT32_C(0x9b05688c);

    context->state[6] =
        UINT32_C(0x1f83d9ab);

    context->state[7] =
        UINT32_C(0x5be0cd19);
}


void nsdiff_sha256_update(
    struct nsdiff_sha256_context *context,
    const void *data,
    size_t size
)
{
    const unsigned char *bytes =
        data;

    context->total_bytes +=
        (uint64_t)size;

    while (size != 0U) {

        size_t available =
            sizeof(context->block) -
            context->block_used;

        size_t chunk =
            size < available
                ? size
                : available;

        memcpy(
            context->block +
                context->block_used,
            bytes,
            chunk
        );

        context->block_used +=
            chunk;

        bytes +=
            chunk;

        size -=
            chunk;

        if (context->block_used ==
            sizeof(context->block)) {

            sha256_transform(
                context,
                context->block
            );

            context->block_used =
                0U;
        }
    }
}


void nsdiff_sha256_final(
    struct nsdiff_sha256_context *context,
    unsigned char digest[
        NSDIFF_SNAPSHOT_SHA256_LEN
    ]
)
{
    uint64_t bit_length =
        context->total_bytes *
        UINT64_C(8);

    size_t i;

    context->block[
        context->block_used++
    ] = 0x80U;

    if (context->block_used >
        56U) {

        while (context->block_used <
               sizeof(context->block)) {

            context->block[
                context->block_used++
            ] = 0U;
        }

        sha256_transform(
            context,
            context->block
        );

        context->block_used =
            0U;
    }

    while (context->block_used <
           56U) {

        context->block[
            context->block_used++
        ] = 0U;
    }

    for (i = 0;
         i < 8U;
         i++) {

        context->block[
            63U - i
        ] =
            (unsigned char)(
                bit_length >>
                (i * 8U)
            );
    }

    sha256_transform(
        context,
        context->block
    );

    for (i = 0;
         i < 8U;
         i++) {

        sha256_store_be32(
            digest + i * 4U,
            context->state[i]
        );
    }
}


void nsdiff_sha256(
    const void *data,
    size_t size,
    unsigned char digest[
        NSDIFF_SNAPSHOT_SHA256_LEN
    ]
)
{
    struct nsdiff_sha256_context context;

    nsdiff_sha256_init(
        &context
    );

    nsdiff_sha256_update(
        &context,
        data,
        size
    );

    nsdiff_sha256_final(
        &context,
        digest
    );
}
