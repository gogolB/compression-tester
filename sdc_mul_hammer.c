/*
 * sdc_mul_hammer.c - AVX512 multiply/FMA hammer with deterministic self-check.
 *
 * Targets the execution units that y-cruncher tripped on (big-integer multiply
 * via AVX512-IFMA vpmadd52, integer vpmullq, and FP vfmadd). The kernel is
 * fully deterministic: given the same seed it must always produce the same
 * 64-bit checksum. We compute a golden checksum once (round 0, or supplied on
 * the command line from a known-good core) and then recompute it in a tight
 * loop. Any deviation is a wrong answer produced by this core = an SDC hit.
 *
 * Build: gcc -O2 -march=icelake-server -o sdc_mul_hammer sdc_mul_hammer.c
 *   (or: -mavx512f -mavx512dq -mavx512ifma)
 *
 * Usage: sdc_mul_hammer <seconds> [expected_hex_checksum]
 *   Pin it with taskset, e.g.:  taskset -c 70,71 ./sdc_mul_hammer 60
 */

#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LANES     8          /* 512-bit / 64-bit */
#define VEC_COUNT 512        /* number of __m512i vectors in the buffer */
#define INNER     4096       /* multiply rounds per checksum */

static inline double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

/*
 * Deterministic heavy multiply kernel -> 64-bit checksum.
 * `salt` is supplied at runtime (same value every call) so the optimizer
 * cannot constant-fold the body, yet the result stays reproducible.
 */
static uint64_t kernel(uint64_t salt) {
    __m512i acc_i = _mm512_set1_epi64(0x9E3779B97F4A7C15ULL ^ salt);
    __m512i mul   = _mm512_set1_epi64(0xD1B54A32D192ED03ULL);
    __m512d acc_f = _mm512_set1_pd(1.0000001);
    __m512d cf    = _mm512_set1_pd(1.0000003);

    /* Seed a working set with fixed, per-lane-distinct values. */
    uint64_t seed[LANES * VEC_COUNT];
    for (int i = 0; i < LANES * VEC_COUNT; i++)
        seed[i] = 0x0123456789ABCDEFULL * (uint64_t)(i + 1) + 0xC0FFEEULL + salt;

    for (int r = 0; r < INNER; r++) {
        for (int v = 0; v < VEC_COUNT; v++) {
            __m512i x = _mm512_loadu_si512((const void *)(seed + v * LANES));
            /* Barrier: force the vector to be materialized each iteration. */
            __asm__ volatile("" : "+v"(x));

            /* AVX512-IFMA 52-bit multiply-add (big-integer path). */
            acc_i = _mm512_madd52lo_epu64(acc_i, x, mul);
            acc_i = _mm512_madd52hi_epu64(acc_i, x, mul);

            /* AVX512-DQ 64-bit integer multiply. */
            acc_i = _mm512_add_epi64(acc_i, _mm512_mullo_epi64(x, mul));

            /* AVX512 FP fused multiply-add. */
            __m512d xf = _mm512_cvtepu64_pd(x);
            acc_f = _mm512_fmadd_pd(xf, cf, acc_f);

            /* Feed results back so a single wrong lane propagates. */
            mul = _mm512_xor_si512(mul, _mm512_srli_epi64(acc_i, 7));
        }
    }

    /* Fold FP into integer accumulator deterministically. */
    uint64_t out[LANES];
    _mm512_storeu_si512((void *)out, acc_i);

    double ftmp[LANES];
    _mm512_storeu_pd(ftmp, acc_f);

    uint64_t chk = 0;
    for (int i = 0; i < LANES; i++) {
        uint64_t fbits;
        memcpy(&fbits, &ftmp[i], sizeof(fbits));
        chk ^= out[i] + 0x9E3779B97F4A7C15ULL * (uint64_t)(i + 1);
        chk = (chk << 13) | (chk >> 51);
        chk += fbits;
    }
    return chk;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <seconds> [expected_hex]\n", argv[0]);
        return 1;
    }
    double seconds = atof(argv[1]);

    /* Runtime-derived but fixed salt: opaque to the optimizer. */
    volatile uint64_t vsalt = 0;
    uint64_t salt = vsalt;

    uint64_t golden = kernel(salt);
    int have_expected = 0;
    if (argc >= 3) {
        golden = (uint64_t)strtoull(argv[2], NULL, 16);
        have_expected = 1;
    }
    printf("golden=%016llx (%s)\n",
           (unsigned long long)golden,
           have_expected ? "supplied" : "self round-0");
    fflush(stdout);

    double end = now_sec() + seconds;
    uint64_t rounds = 0, hits = 0;

    while (now_sec() < end) {
        uint64_t c = kernel(salt);
        if (c != golden) {
            hits++;
            printf("[MISMATCH] round=%llu got=%016llx exp=%016llx\n",
                   (unsigned long long)rounds,
                   (unsigned long long)c,
                   (unsigned long long)golden);
            fflush(stdout);
        }
        rounds++;
    }

    printf("rounds=%llu hits=%llu golden=%016llx\n",
           (unsigned long long)rounds,
           (unsigned long long)hits,
           (unsigned long long)golden);
    return hits ? 2 : 0;
}
