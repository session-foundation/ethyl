// keccak.c
// 19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>
// A baseline Keccak (3rd round) implementation.
//
// This file keeps the existing public API and legacy Keccak padding behavior.
// NOTE: This is legacy Keccak padding 0x01, not SHA3 padding 0x06.

#include "keccak.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

extern "C" {
#include <unistd.h>
}

#include <oxenc/endian.h>

static void local_abort(const char* msg) {
    fprintf(stderr, "%s\n", msg);
#ifdef NDEBUG
    _exit(1);
#else
    abort();
#endif
}

namespace {

constexpr size_t HASH_DATA_AREA = 136;
constexpr size_t KECCAK_BLOCKLEN = 136;
constexpr size_t KECCAK_WORDS = 17;
constexpr size_t KECCAK_DIGESTSIZE = 32;
constexpr uint32_t KECCAK_FINALIZED = 0x80000000u;

using state_t = uint64_t[25];

// Internal linkage keeps these tables local to this translation unit.
// constexpr allows compile-time initialization and avoids exported symbols.
static constexpr uint64_t keccakf_rndc[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
        0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
        0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
        0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
        0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

static constexpr int keccakf_rotc[24] = {
        1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};

static constexpr int keccakf_piln[24] = {
        10, 7,  11, 17, 18, 3,  5,  16, 8,  21, 24, 4,
        15, 23, 19, 13, 12, 2,  20, 14, 22, 9,  6,  1};

static inline void memcpy_swap64le(void* dst, const void* src, size_t n) {
    if constexpr (oxenc::little_endian) {
        std::memcpy(dst, src, n * sizeof(uint64_t));
    } else {
        for (size_t i = 0; i < n; i++)
            static_cast<uint64_t*>(dst)[i] =
                    oxenc::host_to_little(static_cast<const uint64_t*>(src)[i]);
    }
}

// Safer alignment check than subtracting from a null pointer.
// The old macro worked in practice but relied on questionable pointer arithmetic.
static inline bool is_aligned_64(const void* p) {
    return (reinterpret_cast<uintptr_t>(p) & 7u) == 0;
}

static inline void process_block(uint64_t st[25], const uint64_t block[17]) {
    for (size_t i = 0; i < KECCAK_WORDS; i++)
        st[i] ^= oxenc::little_to_host(block[i]);

    keccakf(st, KECCAK_ROUNDS);
}

} // namespace

extern "C" void keccakf(uint64_t st[25], int rounds) {
    uint64_t t;
    uint64_t bc[5];

    for (int round = 0; round < rounds; round++) {
        // Theta.
        bc[0] = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        bc[1] = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        bc[2] = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        bc[3] = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        bc[4] = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

        // Avoid repeated modulo operations in the hot path.
        // This is the same Theta step as before, expanded across the 5 lanes.
        const uint64_t d0 = bc[4] ^ ROTL64(bc[1], 1);
        const uint64_t d1 = bc[0] ^ ROTL64(bc[2], 1);
        const uint64_t d2 = bc[1] ^ ROTL64(bc[3], 1);
        const uint64_t d3 = bc[2] ^ ROTL64(bc[4], 1);
        const uint64_t d4 = bc[3] ^ ROTL64(bc[0], 1);

        st[0] ^= d0;
        st[5] ^= d0;
        st[10] ^= d0;
        st[15] ^= d0;
        st[20] ^= d0;

        st[1] ^= d1;
        st[6] ^= d1;
        st[11] ^= d1;
        st[16] ^= d1;
        st[21] ^= d1;

        st[2] ^= d2;
        st[7] ^= d2;
        st[12] ^= d2;
        st[17] ^= d2;
        st[22] ^= d2;

        st[3] ^= d3;
        st[8] ^= d3;
        st[13] ^= d3;
        st[18] ^= d3;
        st[23] ^= d3;

        st[4] ^= d4;
        st[9] ^= d4;
        st[14] ^= d4;
        st[19] ^= d4;
        st[24] ^= d4;

        // Rho + Pi.
        // Kept table-driven for readability and to avoid a large unrolled block.
        t = st[1];
        for (int i = 0; i < 24; i++) {
            const int j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        // Chi.
        // Load each row into local variables once and write the transformed row back.
        // This avoids modulo indexing inside the inner loop.
        for (int j = 0; j < 25; j += 5) {
            const uint64_t a0 = st[j + 0];
            const uint64_t a1 = st[j + 1];
            const uint64_t a2 = st[j + 2];
            const uint64_t a3 = st[j + 3];
            const uint64_t a4 = st[j + 4];

            st[j + 0] = a0 ^ ((~a1) & a2);
            st[j + 1] = a1 ^ ((~a2) & a3);
            st[j + 2] = a2 ^ ((~a3) & a4);
            st[j + 3] = a3 ^ ((~a4) & a0);
            st[j + 4] = a4 ^ ((~a0) & a1);
        }

        // Iota.
        st[0] ^= keccakf_rndc[round];
    }
}

extern "C" void keccak(const uint8_t* in, size_t inlen, uint8_t* md, size_t mdlen) {
    state_t st{};
    uint8_t temp[HASH_DATA_AREA]{};

    if (!md || mdlen == 0 || (mdlen > 100 && sizeof(st) != mdlen)) {
        local_abort("Bad keccak use");
    }

    if ((mdlen % sizeof(uint64_t)) != 0) {
        local_abort("Bad keccak use");
    }

    const size_t rsiz = sizeof(state_t) == mdlen ? HASH_DATA_AREA : 200 - 2 * mdlen;
    const size_t rsizw = rsiz / 8;

    if (rsiz == 0 || rsiz > HASH_DATA_AREA || (rsiz % 8) != 0) {
        local_abort("Bad keccak use");
    }

    while (inlen >= rsiz) {
        for (size_t i = 0; i < rsizw; i++)
            st[i] ^= oxenc::load_little_to_host<uint64_t>(in + i * 8);

        keccakf(st, KECCAK_ROUNDS);

        in += rsiz;
        inlen -= rsiz;
    }

    // Final block and padding.
    // temp is zero-initialized, so no separate memset is needed for the tail.
    // Padding remains legacy Keccak: 0x01 ... 0x80.
    if (inlen > rsiz) {
        local_abort("Bad keccak use");
    }

    if (inlen > 0)
        std::memcpy(temp, in, inlen);

    temp[inlen] = 0x01;
    temp[rsiz - 1] |= 0x80;

    for (size_t i = 0; i < rsizw; i++)
        st[i] ^= oxenc::load_little_to_host<uint64_t>(temp + i * 8);

    keccakf(st, KECCAK_ROUNDS);

    memcpy_swap64le(md, st, mdlen / sizeof(uint64_t));
}

extern "C" void keccak1600(const uint8_t* in, size_t inlen, uint8_t* md) {
    keccak(in, inlen, md, sizeof(state_t));
}

extern "C" void keccak_init(KECCAK_CTX* ctx) {
    if (!ctx)
        local_abort("Bad keccak use");

    std::memset(ctx, 0, sizeof(KECCAK_CTX));
}

extern "C" void keccak_update(KECCAK_CTX* ctx, const uint8_t* in, size_t inlen) {
    if (!ctx || (!in && inlen))
        local_abort("Bad keccak use");

    if (ctx->rest & KECCAK_FINALIZED)
        local_abort("Bad keccak use");

    const size_t idx = ctx->rest;
    ctx->rest = (ctx->rest + inlen) % KECCAK_BLOCKLEN;

    // Fill existing partial block first.
    if (idx) {
        const size_t left = KECCAK_BLOCKLEN - idx;
        const size_t take = inlen < left ? inlen : left;

        std::memcpy(reinterpret_cast<uint8_t*>(ctx->message) + idx, in, take);

        if (inlen < left)
            return;

        process_block(ctx->hash, ctx->message);

        in += left;
        inlen -= left;
    }

    // Process complete blocks directly when 64-bit aligned.
    // Otherwise copy to the aligned context buffer first.
    while (inlen >= KECCAK_BLOCKLEN) {
        if (is_aligned_64(in)) {
            process_block(ctx->hash, reinterpret_cast<const uint64_t*>(in));
        } else {
            std::memcpy(ctx->message, in, KECCAK_BLOCKLEN);
            process_block(ctx->hash, ctx->message);
        }

        in += KECCAK_BLOCKLEN;
        inlen -= KECCAK_BLOCKLEN;
    }

    // Store remaining partial block.
    if (inlen)
        std::memcpy(ctx->message, in, inlen);
}

extern "C" void keccak_finish(KECCAK_CTX* ctx, uint8_t* md) {
    if (!ctx)
        local_abort("Bad keccak use");

    if (!(ctx->rest & KECCAK_FINALIZED)) {
        const size_t rest = ctx->rest;

        std::memset(
                reinterpret_cast<uint8_t*>(ctx->message) + rest,
                0,
                KECCAK_BLOCKLEN - rest);

        // Legacy Keccak padding, not SHA3 padding.
        reinterpret_cast<uint8_t*>(ctx->message)[rest] |= 0x01;
        reinterpret_cast<uint8_t*>(ctx->message)[KECCAK_BLOCKLEN - 1] |= 0x80;

        process_block(ctx->hash, ctx->message);

        ctx->rest = KECCAK_FINALIZED;
    }

    static_assert(KECCAK_BLOCKLEN > KECCAK_DIGESTSIZE, "");
    static_assert(KECCAK_DIGESTSIZE % sizeof(uint64_t) == 0, "");

    if (md)
        memcpy_swap64le(md, ctx->hash, KECCAK_DIGESTSIZE / sizeof(uint64_t));
}