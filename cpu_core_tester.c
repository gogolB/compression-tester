#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <zlib.h>
#include <zstd.h>
#include <lz4.h>
#include <lzma.h>

#include <openssl/sha.h>

#define DEFAULT_ITERATIONS 100
#define DEFAULT_BLOCK_MB 16
#define MAX_CORES 1024
#define NUM_ALGORITHMS 3   /* zlib, zstd, lz4 */

/* Test data generation (fill_layer_data) */
#define PATTERN_CHUNK_BYTES 4096
#define NUM_DATA_PATTERNS 8
#define FALLBACK_SEED 0xDEADBEEFCAFEBABEULL
#define GOLDEN_RATIO_64 0x9E3779B97F4A7C15ULL /* 2^64/phi: mixes core id into seeds */

/* xorshift64 PRNG shift parameters */
#define XORSHIFT_SHIFT_A 12
#define XORSHIFT_SHIFT_B 25
#define XORSHIFT_SHIFT_C 27

#define ZSTD_COMPRESSION_LEVEL 3
#define VERBOSE_INTERVAL 10  /* iterations between progress reports */

/* Vote mode: all cores run identical input per round; the coordinator
 * compares SHA256 digests of the COMPRESSED output across cores and
 * majority-rules. Compressed bytes are compared (not decompressed)
 * because a wrong-but-self-consistent compression passes a round-trip
 * check but differs from every healthy core - and because Docker's blob
 * digest is over compressed data too. Assumes homogeneous cores (same
 * uarch => same library dispatch => deterministic compressed bytes). */
#define VOTE_BASE_SEED 0xB07E000000000000ULL /* shared by all cores in vote mode */

/* Guard canaries: magic bands around buffers to catch stray writes */
#define GUARD_BAND_BYTES 64
#define GUARD_MAGIC 0xDEADBEEFC0DEC0DEULL

/* Known-answer test: golden digests for fixed vectors, precomputed on a
 * trusted machine (regenerate with: make kat-dump). Block size is fixed
 * because the baked-in digests depend on it. */
#define KAT_BLOCK_MB 4
#define KAT_BLOCK_BYTES ((size_t)KAT_BLOCK_MB * 1024 * 1024)
#define KAT_VECTOR_COUNT 3

/* Exit codes: bit 0 = bad cores found, bit 1 = some cores untested */
#define EXIT_CLEAN     0
#define EXIT_BAD_CORES 1
#define EXIT_UNTESTED  2

typedef enum {
    ALG_ZLIB,
    ALG_ZSTD,
    ALG_LZ4,
    ALG_XZ,
    ALG_MEMCPY,
    ALG_HAMMER,
    ALG_ALL,
} algorithm_t;

typedef enum {
    MODE_SEQUENTIAL,
    MODE_PARALLEL,
    MODE_BOTH,
} run_mode_t;

typedef struct {
    int iterations;
    size_t data_size;
    algorithm_t algorithm;
    int verbose;
    int kat;
    int iopath;              /* route blobs through the kernel (tmpfs), like docker */
    int burst_ms;            /* idle gap between iterations; 0 = continuous */
    int duration_sec;        /* wall-clock dwell; 0 = use iterations instead */
} run_opts_t;

typedef struct {
    int core_id;
    int iterations;
    size_t data_size;
    algorithm_t algorithm;
    int *error_count;        /* per-core slot, written only by this worker */
    int *tested;             /* per-core slot: set to 1 only if the workload ran */
    pthread_mutex_t *print_mutex;
    int verbose;
    int kat;
    int iopath;
    int burst_ms;
    time_t end_time;         /* if nonzero, loop until this time (duration mode) */
    int vote;
    uint8_t *vote_digests;     /* per-core buffer: iterations*alg_count digests, or NULL */
} worker_args_t;

/* Writable tmpfs directory for --iopath, picked at startup. */
static const char *g_iopath_dir = "/dev/shm";

static volatile int g_shutdown = 0;

static void signal_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
}

/*
 * Generate varied data patterns that exercise different parts of the CPU.
 * Docker layers contain a mix of: zeros, repeated bytes, random data,
 * text-like sequences, and compressed-already data. Patterns 5-7 are
 * classic bit-stress patterns (alternating bits, all ones, walking one)
 * that make faults show up at recognizable bit positions.
 *
 * The seed makes every iteration use a different buffer: marginal cores
 * usually fail only on specific data patterns, so identical input every
 * iteration drastically reduces the chance of catching them.
 *
 * NOTE: the KAT golden digests below depend on this function's exact
 * output. If you change it, regenerate them (make kat-dump) on a
 * TRUSTED machine.
 */
static void fill_layer_data(uint8_t *buf, size_t size, uint64_t seed) {
    size_t pos = 0;
    uint64_t rng = seed ? seed : FALLBACK_SEED;

    while (pos < size) {
        size_t chunk = (size - pos > PATTERN_CHUNK_BYTES) ? PATTERN_CHUNK_BYTES : size - pos;

        uint8_t pattern = (uint8_t)(((pos / PATTERN_CHUNK_BYTES) + seed) % NUM_DATA_PATTERNS);
        switch (pattern) {
            case 0:
                memset(buf + pos, 0, chunk);
                break;
            case 1:
                memset(buf + pos, (int)(seed & 0xFF), chunk);
                break;
            case 2:
                for (size_t i = 0; i < chunk; i++)
                    buf[pos + i] = (uint8_t)((i + seed) & 0xFF);
                break;
            case 3:
                for (size_t i = 0; i < chunk; i++) {
                    rng ^= rng >> XORSHIFT_SHIFT_A;
                    rng ^= rng << XORSHIFT_SHIFT_B;
                    rng ^= rng >> XORSHIFT_SHIFT_C;
                    buf[pos + i] = (uint8_t)(rng & 0xFF);
                }
                break;
            case 4:
                for (size_t i = 0; i < chunk; i++)
                    buf[pos + i] = (uint8_t)('A' + ((i + seed) % 26));
                break;
            case 5:
                memset(buf + pos, 0x55, chunk); /* alternating bits 01010101 */
                break;
            case 6:
                memset(buf + pos, 0xFF, chunk); /* all ones */
                break;
            case 7:
                for (size_t i = 0; i < chunk; i++) /* walking one */
                    buf[pos + i] = (uint8_t)(1U << ((pos + i) & 7));
                break;
        }
        pos += chunk;
    }
}

/*
 * Guard canaries: allocate size bytes with a magic band on each side.
 * A failing core that computes a bad pointer and writes out of bounds
 * corrupts a band, which guard_check then catches. 128 bytes of overhead
 * per buffer: negligible.
 */
static uint8_t *guarded_malloc(size_t size) {
    uint8_t *raw = malloc(size + 2 * GUARD_BAND_BYTES);
    if (!raw)
        return NULL;
    for (size_t i = 0; i < GUARD_BAND_BYTES; i += sizeof(uint64_t)) {
        uint64_t m = GUARD_MAGIC;
        memcpy(raw + i, &m, sizeof(m));
        memcpy(raw + GUARD_BAND_BYTES + size + i, &m, sizeof(m));
    }
    return raw + GUARD_BAND_BYTES;
}

/* Returns 0 if both bands are intact, -1 on a stray write. */
static int guard_check(const uint8_t *p, size_t size) {
    const uint8_t *raw = p - GUARD_BAND_BYTES;
    for (size_t i = 0; i < GUARD_BAND_BYTES; i += sizeof(uint64_t)) {
        uint64_t v;
        memcpy(&v, raw + i, sizeof(v));
        if (v != GUARD_MAGIC)
            return -1;
        memcpy(&v, raw + GUARD_BAND_BYTES + size + i, sizeof(v));
        if (v != GUARD_MAGIC)
            return -1;
    }
    return 0;
}

static void guarded_free(void *p) {
    if (p)
        free((uint8_t *)p - GUARD_BAND_BYTES);
}

/*
 * Unit hammer (-a hammer): deterministic multiply/FMA kernel targeting the
 * execution units generic codec workloads never touch - AVX512-IFMA
 * vpmadd52, vpmullq, FP FMA; AVX2 vpmuludq/vpmulld/FMA; scalar imul.
 * Modeled on the coworker's sdc_mul_hammer.c, but with runtime dispatch
 * via GCC/Clang function target attributes, so one portable binary runs
 * on any x86-64 and picks the best kernel the CPU supports (no SIGILL on
 * older Xeons). Golden is the worker's round-0 checksum; --vote compares
 * hammer checksums across cores, which closes the self-reference hole a
 * round-0 golden has on a deterministically-wrong core.
 */
#define HAMMER_INNER 4096
#define HAMMER_VECS 512

typedef uint64_t (*hammer_fn)(uint64_t salt);
static hammer_fn g_hammer;
static const char *g_hammer_name;

static uint64_t hammer_scalar(uint64_t salt) {
    uint64_t acc = 0x9E3779B97F4A7C15ULL ^ salt;
    uint64_t mul = 0xD1B54A32D192ED03ULL;
    uint64_t buf[HAMMER_VECS];
    for (int i = 0; i < HAMMER_VECS; i++)
        buf[i] = 0x0123456789ABCDEFULL * (uint64_t)(i + 1) + 0xC0FFEEULL + salt;

    for (int r = 0; r < HAMMER_INNER; r++) {
        for (int v = 0; v < HAMMER_VECS; v++) {
            uint64_t x = buf[v];
            __asm__ volatile("" : "+r"(x)); /* stop the optimizer folding this */
            acc += x * mul;                 /* integer multiply chain */
            mul ^= acc >> 7;
        }
    }
    return acc ^ (mul * 0x9E3779B97F4A7C15ULL);
}

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#define HAVE_X86_HAMMER 1
#include <immintrin.h>

/* AVX512-IFMA big-integer multiply-add + vpmullq + FP FMA (Ice Lake+). */
__attribute__((target("avx512f,avx512dq,avx512ifma")))
static uint64_t hammer_avx512(uint64_t salt) {
    __m512i acc_i = _mm512_set1_epi64(0x9E3779B97F4A7C15ULL ^ salt);
    __m512i mul   = _mm512_set1_epi64(0xD1B54A32D192ED03ULL);
    __m512d acc_f = _mm512_set1_pd(1.0000001);
    __m512d cf    = _mm512_set1_pd(1.0000003);

    uint64_t seed[8 * HAMMER_VECS];
    for (int i = 0; i < 8 * HAMMER_VECS; i++)
        seed[i] = 0x0123456789ABCDEFULL * (uint64_t)(i + 1) + 0xC0FFEEULL + salt;

    for (int r = 0; r < HAMMER_INNER; r++) {
        for (int v = 0; v < HAMMER_VECS; v++) {
            __m512i x = _mm512_loadu_si512((const void *)(seed + v * 8));
            __asm__ volatile("" : "+v"(x));

            acc_i = _mm512_madd52lo_epu64(acc_i, x, mul);
            acc_i = _mm512_madd52hi_epu64(acc_i, x, mul);
            acc_i = _mm512_add_epi64(acc_i, _mm512_mullo_epi64(x, mul));

            __m512d xf = _mm512_cvtepu64_pd(x);
            acc_f = _mm512_fmadd_pd(xf, cf, acc_f);

            mul = _mm512_xor_si512(mul, _mm512_srli_epi64(acc_i, 7));
        }
    }

    uint64_t out[8];
    _mm512_storeu_si512((void *)out, acc_i);
    double ftmp[8];
    _mm512_storeu_pd(ftmp, acc_f);

    uint64_t chk = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t fbits;
        memcpy(&fbits, &ftmp[i], sizeof(fbits));
        chk ^= out[i] + 0x9E3779B97F4A7C15ULL * (uint64_t)(i + 1);
        chk = (chk << 13) | (chk >> 51);
        chk += fbits;
    }
    return chk;
}

/* AVX2/FMA fallback: vpmuludq both halves + vpmulld + FP FMA. */
__attribute__((target("avx2,fma")))
static uint64_t hammer_avx2(uint64_t salt) {
    __m256i acc_i = _mm256_set1_epi64x(0x9E3779B97F4A7C15ULL ^ salt);
    __m256i mul   = _mm256_set1_epi64x(0xD1B54A32D192ED03ULL);
    __m256d acc_f = _mm256_set1_pd(1.0000001);
    __m256d cf    = _mm256_set1_pd(1.0000003);

    uint64_t seed[4 * HAMMER_VECS];
    for (int i = 0; i < 4 * HAMMER_VECS; i++)
        seed[i] = 0x0123456789ABCDEFULL * (uint64_t)(i + 1) + 0xC0FFEEULL + salt;

    for (int r = 0; r < HAMMER_INNER; r++) {
        for (int v = 0; v < HAMMER_VECS; v++) {
            __m256i x = _mm256_loadu_si256((const __m256i *)(seed + v * 4));
            __asm__ volatile("" : "+x"(x));

            __m256i lo = _mm256_mul_epu32(x, mul);
            __m256i hi = _mm256_mul_epu32(_mm256_srli_epi64(x, 32),
                                          _mm256_srli_epi64(mul, 32));
            acc_i = _mm256_add_epi64(acc_i, _mm256_add_epi64(lo, hi));
            acc_i = _mm256_add_epi64(acc_i, _mm256_mullo_epi32(x, mul));

            __m256d xf = _mm256_cvtepi32_pd(_mm256_castsi256_si128(x));
            acc_f = _mm256_fmadd_pd(xf, cf, acc_f);

            mul = _mm256_xor_si256(mul, _mm256_srli_epi64(acc_i, 7));
        }
    }

    uint64_t out[4];
    _mm256_storeu_si256((__m256i *)out, acc_i);
    double ftmp[4];
    _mm256_storeu_pd(ftmp, acc_f);

    uint64_t chk = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t fbits;
        memcpy(&fbits, &ftmp[i], sizeof(fbits));
        chk ^= out[i] + 0x9E3779B97F4A7C15ULL * (uint64_t)(i + 1);
        chk = (chk << 13) | (chk >> 51);
        chk += fbits;
    }
    return chk;
}
#endif /* __x86_64__ */

static void hammer_init(void) {
#if HAVE_X86_HAMMER
    __builtin_cpu_init();
    if (__builtin_cpu_supports("avx512ifma") && __builtin_cpu_supports("avx512dq")) {
        g_hammer = hammer_avx512;
        g_hammer_name = "avx512-ifma (vpmadd52/vpmullq/fmadd)";
        return;
    }
    if (__builtin_cpu_supports("avx2") && __builtin_cpu_supports("fma")) {
        g_hammer = hammer_avx2;
        g_hammer_name = "avx2+fma (vpmuludq/vpmulld/fmadd)";
        return;
    }
#endif
    g_hammer = hammer_scalar;
    g_hammer_name = "scalar (imul)";
}

/*
 * Known-answer test vectors. The digests are golden values computed on a
 * TRUSTED machine ("make kat-dump" prints a fresh table). The suspect
 * core must reproduce them exactly, so verification never relies on any
 * value computed by the core under test itself. Digests depend on
 * fill_layer_data() and KAT_BLOCK_BYTES.
 */
typedef struct {
    uint64_t seed;
    uint8_t digest[SHA256_DIGEST_LENGTH];
} kat_vector_t;

static const kat_vector_t KAT_VECTORS[KAT_VECTOR_COUNT] = {
    { 0xC0DEC0DE00000001ULL, {
        0x55, 0xC1, 0xC0, 0x93, 0xAB, 0x58, 0xBE, 0x8B,
        0x25, 0xCB, 0xD2, 0x63, 0xED, 0x07, 0xB5, 0xE9,
        0x6B, 0xD4, 0xBA, 0x3B, 0x60, 0x14, 0x52, 0x2D,
        0x54, 0x2A, 0x73, 0x5B, 0xFC, 0x1C, 0xCE, 0xC6,
    } },
    { 0xC0DEC0DE00000002ULL, {
        0xF7, 0xF8, 0x94, 0x2F, 0x94, 0xFF, 0xE8, 0x2D,
        0x72, 0x74, 0x7B, 0x56, 0xB1, 0xF9, 0x8A, 0x6B,
        0xE8, 0x05, 0x21, 0xBC, 0x52, 0x5A, 0x49, 0x07,
        0x50, 0xE1, 0x89, 0x1B, 0x0B, 0x35, 0x18, 0x2E,
    } },
    { 0xC0DEC0DE00000003ULL, {
        0x13, 0xB6, 0xD6, 0x62, 0xFF, 0x0C, 0x78, 0x5F,
        0xE1, 0xD4, 0xE9, 0x7A, 0x61, 0xD8, 0xEE, 0x3F,
        0x28, 0xD7, 0xE2, 0xFD, 0xD4, 0x4B, 0x79, 0x42,
        0x90, 0x80, 0xDD, 0xD4, 0xA0, 0x06, 0x89, 0x25,
    } },
};

/*
 * SHA256 a buffer. Returns 0 on match, -1 on mismatch.
 * This mirrors Docker's layer digest verification.
 */
static int sha256_verify(const uint8_t *data, size_t len,
                          const uint8_t expected[SHA256_DIGEST_LENGTH]) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);
    return memcmp(hash, expected, SHA256_DIGEST_LENGTH) == 0 ? 0 : -1;
}

/*
 * Verify the round-trip output. memcmp is the deterministic check; SHA256
 * mirrors the Docker digest verification on top of it.
 */
static int verify_output(const uint8_t *original, const uint8_t *decompressed,
                          size_t data_size, const uint8_t expected_hash[SHA256_DIGEST_LENGTH]) {
    if (memcmp(decompressed, original, data_size) != 0)
        return -1;
    return sha256_verify(decompressed, data_size, expected_hash);
}

/*
 * Compress -> decompress -> verify.
 * Mirrors the Docker pull pipeline for a single layer chunk.
 * Returns 0 if the round-trip produces identical, hash-verified output.
 */
static int test_zlib(const uint8_t *data, size_t data_size,
                      const uint8_t expected_hash[SHA256_DIGEST_LENGTH],
                      uint8_t *comp_digest) {
    uLong comp_bound = compressBound(data_size);
    Bytef *compressed = malloc(comp_bound);
    Bytef *decompressed = (Bytef *)guarded_malloc(data_size);
    if (!compressed || !decompressed) {
        free(compressed); guarded_free(decompressed);
        return -1;
    }

    z_stream c_stream = {0};
    if (deflateInit(&c_stream, Z_DEFAULT_COMPRESSION) != Z_OK) {
        free(compressed); guarded_free(decompressed);
        return -1;
    }
    c_stream.next_in = (Bytef *)data;
    c_stream.avail_in = data_size;
    c_stream.next_out = compressed;
    c_stream.avail_out = comp_bound;

    if (deflate(&c_stream, Z_FINISH) != Z_STREAM_END) {
        deflateEnd(&c_stream);
        free(compressed); guarded_free(decompressed);
        return -1;
    }
    uLong comp_size = c_stream.total_out;
    deflateEnd(&c_stream);
    if (comp_digest)
        SHA256(compressed, comp_size, comp_digest);

    z_stream d_stream = {0};
    if (inflateInit(&d_stream) != Z_OK) {
        free(compressed); guarded_free(decompressed);
        return -1;
    }
    d_stream.next_in = compressed;
    d_stream.avail_in = comp_size;
    d_stream.next_out = decompressed;
    d_stream.avail_out = data_size;

    if (inflate(&d_stream, Z_FINISH) != Z_STREAM_END) {
        inflateEnd(&d_stream);
        free(compressed); guarded_free(decompressed);
        return -1;
    }
    uLong decomp_size = d_stream.total_out;
    inflateEnd(&d_stream);

    int result = 0;
    if (decomp_size != data_size) {
        result = -1;
    } else {
        result = verify_output(data, decompressed, data_size, expected_hash);
    }
    if (guard_check(decompressed, data_size) != 0)
        result = -1;

    free(compressed);
    guarded_free(decompressed);
    return result;
}

static int test_zstd(const uint8_t *data, size_t data_size,
                      const uint8_t expected_hash[SHA256_DIGEST_LENGTH],
                      uint8_t *comp_digest) {
    size_t comp_bound = ZSTD_compressBound(data_size);
    uint8_t *compressed = malloc(comp_bound);
    uint8_t *decompressed = guarded_malloc(data_size);
    if (!compressed || !decompressed) {
        free(compressed); guarded_free(decompressed);
        return -1;
    }

    size_t comp_size = ZSTD_compress(compressed, comp_bound, data, data_size,
                                       ZSTD_COMPRESSION_LEVEL);
    if (ZSTD_isError(comp_size)) {
        free(compressed); guarded_free(decompressed);
        return -1;
    }
    if (comp_digest)
        SHA256(compressed, comp_size, comp_digest);

    size_t decomp_size = ZSTD_decompress(decompressed, data_size, compressed, comp_size);
    if (ZSTD_isError(decomp_size)) {
        free(compressed); guarded_free(decompressed);
        return -1;
    }

    int result = 0;
    if (decomp_size != data_size) {
        result = -1;
    } else {
        result = verify_output(data, decompressed, data_size, expected_hash);
    }
    if (guard_check(decompressed, data_size) != 0)
        result = -1;

    free(compressed);
    guarded_free(decompressed);
    return result;
}

static int test_lz4(const uint8_t *data, size_t data_size,
                     const uint8_t expected_hash[SHA256_DIGEST_LENGTH],
                     uint8_t *comp_digest) {
    int comp_bound = LZ4_compressBound(data_size);
    char *compressed = malloc(comp_bound);
    char *decompressed = (char *)guarded_malloc(data_size);
    if (!compressed || !decompressed) {
        free(compressed); guarded_free(decompressed);
        return -1;
    }

    int comp_size = LZ4_compress_default((const char *)data, compressed,
                                           data_size, comp_bound);
    if (comp_size <= 0) {
        free(compressed); guarded_free(decompressed);
        return -1;
    }
    if (comp_digest)
        SHA256((const uint8_t *)compressed, (size_t)comp_size, comp_digest);

    int decomp_size = LZ4_decompress_safe(compressed, decompressed,
                                            comp_size, data_size);

    int result = 0;
    if (decomp_size != (int)data_size) {
        result = -1;
    } else {
        result = verify_output(data, (uint8_t *)decompressed, data_size, expected_hash);
    }
    if (guard_check((const uint8_t *)decompressed, data_size) != 0)
        result = -1;

    free(compressed);
    guarded_free(decompressed);
    return result;
}

/*
 * xz/LZMA (-a xz): range-coder workload, much heavier integer path than
 * deflate-style codecs. LZMA_CHECK_CRC64 gives the decompressor's own
 * integrity check as a second, independent verification.
 */
static int test_xz(const uint8_t *data, size_t data_size,
                    const uint8_t expected_hash[SHA256_DIGEST_LENGTH],
                    uint8_t *comp_digest) {
    size_t bound = lzma_stream_buffer_bound(data_size);
    uint8_t *compressed = malloc(bound);
    uint8_t *decompressed = guarded_malloc(data_size);
    if (!compressed || !decompressed) {
        free(compressed); guarded_free(decompressed);
        return -1;
    }

    size_t comp_size = 0;
    lzma_ret enc = lzma_easy_buffer_encode(LZMA_PRESET_DEFAULT, LZMA_CHECK_CRC64,
                                            NULL, data, data_size,
                                            compressed, &comp_size, bound);
    if (enc != LZMA_OK) {
        free(compressed); guarded_free(decompressed);
        return -1;
    }
    if (comp_digest)
        SHA256(compressed, comp_size, comp_digest);

    size_t in_pos = 0, out_pos = 0;
    uint64_t memlimit = UINT64_MAX;
    lzma_ret dec = lzma_stream_buffer_decode(&memlimit, 0, NULL,
                                              compressed, &in_pos, comp_size,
                                              decompressed, &out_pos, data_size);

    int result = 0;
    if (dec != LZMA_OK || out_pos != data_size) {
        result = -1;
    } else {
        result = verify_output(data, decompressed, data_size, expected_hash);
    }
    if (guard_check(decompressed, data_size) != 0)
        result = -1;

    free(compressed);
    guarded_free(decompressed);
    return result;
}

/*
 * Memory-path workout (-a memcpy): no codec, just bulk copies through the
 * core<->cache<->IMC<->DRAM path, verified at each step. Compression is
 * compute-bound and under-stresses the memory path; saturated memcpy
 * hammers load/store ports, cache fill/evict and the memory controller
 * per unit time. Discriminates: codecs pass + memcpy fails = memory path;
 * both fail = execution core. Use a block larger than L3 so traffic
 * reaches DRAM; RAM cost is ~3x block size per tested core.
 */
static int test_memcpy(const uint8_t *data, size_t data_size,
                        const uint8_t expected_hash[SHA256_DIGEST_LENGTH],
                        uint8_t *comp_digest) {
    uint8_t *copy = guarded_malloc(data_size);
    uint8_t *copy_back = guarded_malloc(data_size);
    if (!copy || !copy_back) {
        guarded_free(copy); guarded_free(copy_back);
        return -1;
    }

    memcpy(copy, data, data_size);       /* stores: core -> caches -> DRAM */
    memcpy(copy_back, copy, data_size);  /* loads + stores back the other way */

    if (comp_digest)
        SHA256(copy_back, data_size, comp_digest);

    int result = verify_output(data, copy_back, data_size, expected_hash);
    if (guard_check(copy, data_size) != 0 ||
        guard_check(copy_back, data_size) != 0)
        result = -1;

    guarded_free(copy);
    guarded_free(copy_back);
    return result;
}

/*
 * Kernel I/O path (--iopath).
 *
 * A docker pull does not decompress in a userspace vacuum: the layer blob
 * travels NIC -> kernel network stack -> page cache -> copy_to_user into
 * dockerd -> decompress -> copy_from_user -> overlayfs. A core with a
 * marginal cache/memory-movement path can corrupt data while executing
 * KERNEL copy code and still pass every pinned userspace test. This path
 * therefore pushes every blob through a tmpfs file (write + read back,
 * i.e. copy_from_user + copy_to_user + page cache) on the pinned core,
 * mirroring docker's actual data path without involving a disk.
 */

static size_t iopath_compress(algorithm_t alg, uint8_t *dst, size_t cap,
                               const uint8_t *src, size_t n) {
    switch (alg) {
        case ALG_ZSTD: {
            size_t r = ZSTD_compress(dst, cap, src, n, ZSTD_COMPRESSION_LEVEL);
            return ZSTD_isError(r) ? 0 : r;
        }
        case ALG_LZ4:
            return (size_t)LZ4_compress_default((const char *)src, (char *)dst, n, cap);
        case ALG_ZLIB: {
            uLongf blen = cap;
            return compress2(dst, &blen, src, n, Z_DEFAULT_COMPRESSION) == Z_OK ? blen : 0;
        }
        case ALG_XZ: {
            size_t out_pos = 0;
            return lzma_easy_buffer_encode(LZMA_PRESET_DEFAULT, LZMA_CHECK_CRC64,
                                           NULL, src, n, dst, &out_pos,
                                           cap) == LZMA_OK ? out_pos : 0;
        }
        default:
            return 0;
    }
}

static size_t iopath_decompress(algorithm_t alg, uint8_t *dst, size_t cap,
                                 const uint8_t *src, size_t n) {
    switch (alg) {
        case ALG_ZSTD: {
            size_t r = ZSTD_decompress(dst, cap, src, n);
            return ZSTD_isError(r) ? 0 : r;
        }
        case ALG_LZ4: {
            int r = LZ4_decompress_safe((const char *)src, (char *)dst, n, cap);
            return r < 0 ? 0 : (size_t)r;
        }
        case ALG_ZLIB: {
            uLongf blen = cap;
            return uncompress(dst, &blen, src, n) == Z_OK ? blen : 0;
        }
        case ALG_XZ: {
            size_t in_pos = 0, out_pos = 0;
            uint64_t memlimit = UINT64_MAX;
            return lzma_stream_buffer_decode(&memlimit, 0, NULL, src, &in_pos, n,
                                             dst, &out_pos, cap) == LZMA_OK ? out_pos : 0;
        }
        default:
            return 0;
    }
}

/*
 * Write a buffer to a tmpfs file and read it back. Returns the number of
 * bytes read back, or (size_t)-1 on error.
 */
static size_t kernel_roundtrip(const uint8_t *in, size_t size, uint8_t *out, int core_id) {
    char path[128];
    snprintf(path, sizeof(path), "%s/cct_%ld_%d", g_iopath_dir, (long)getpid(), core_id);

    int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0)
        return (size_t)-1;

    size_t off = 0;
    while (off < size) {
        ssize_t w = write(fd, in + off, size - off);
        if (w <= 0) { close(fd); unlink(path); return (size_t)-1; }
        off += (size_t)w;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) { close(fd); unlink(path); return (size_t)-1; }
    off = 0;
    while (off < size) {
        ssize_t r = read(fd, out + off, size - off);
        if (r <= 0) { close(fd); unlink(path); return (size_t)-1; }
        off += (size_t)r;
    }

    close(fd);
    unlink(path);
    return off;
}

/*
 * Compress -> kernel round-trip (tmpfs write + read back) -> blob compare
 * -> decompress -> verify. The blob compare is the direct analog of
 * docker's compressed-layer digest check.
 */
static int test_iopath(algorithm_t alg, const uint8_t *data, size_t data_size,
                        const uint8_t expected_hash[SHA256_DIGEST_LENGTH],
                        uint8_t *comp_digest, int core_id) {
    /* Largest of the libraries' bounds (lzma's exceeds zstd's). */
    size_t bound = ZSTD_compressBound(data_size);
    size_t xz_bound = lzma_stream_buffer_bound(data_size);
    if (xz_bound > bound)
        bound = xz_bound;
    uint8_t *comp = malloc(bound);
    uint8_t *comp_back = malloc(bound);
    uint8_t *decomp = guarded_malloc(data_size);
    if (!comp || !comp_back || !decomp) {
        free(comp); free(comp_back); guarded_free(decomp);
        return -1;
    }

    /* For ALG_MEMCPY there is no codec: the raw block itself goes through
     * the kernel path (mirrors the untar/apply side of a docker pull). */
    size_t comp_size;
    if (alg == ALG_MEMCPY) {
        memcpy(comp, data, data_size);
        comp_size = data_size;
    } else {
        comp_size = iopath_compress(alg, comp, bound, data, data_size);
    }
    if (comp_size == 0 ||
        kernel_roundtrip(comp, comp_size, comp_back, core_id) != comp_size ||
        memcmp(comp, comp_back, comp_size) != 0) {
        free(comp); free(comp_back); guarded_free(decomp);
        return -1;
    }

    if (comp_digest)
        SHA256(comp_back, comp_size, comp_digest);

    size_t decomp_size;
    if (alg == ALG_MEMCPY) {
        memcpy(decomp, comp_back, comp_size);
        decomp_size = comp_size;
    } else {
        decomp_size = iopath_decompress(alg, decomp, data_size, comp_back, comp_size);
    }

    int result = 0;
    if (decomp_size != data_size) {
        result = -1;
    } else {
        result = verify_output(data, decomp, data_size, expected_hash);
    }
    if (guard_check(decomp, data_size) != 0)
        result = -1;

    free(comp);
    free(comp_back);
    guarded_free(decomp);
    return result;
}

/* Find a writable tmpfs for --iopath, or NULL. */
static const char *pick_iopath_dir(void) {
    static const char *candidates[] = { "/dev/shm", "/tmp", NULL };
    for (int i = 0; candidates[i]; i++) {
        char probe[128];
        snprintf(probe, sizeof(probe), "%s/cct_probe_%ld", candidates[i], (long)getpid());
        int fd = open(probe, O_CREAT | O_WRONLY | O_EXCL, 0600);
        if (fd >= 0) {
            close(fd);
            unlink(probe);
            return candidates[i];
        }
    }
    return NULL;
}

static const char *alg_name(algorithm_t alg) {
    switch (alg) {
        case ALG_ZLIB: return "zlib";
        case ALG_ZSTD: return "zstd";
        case ALG_LZ4:  return "lz4";
        case ALG_XZ:   return "xz";
        case ALG_MEMCPY: return "memcpy";
        case ALG_HAMMER: return "hammer";
        default:       return "unknown";
    }
}

static int run_algorithm(algorithm_t alg, const uint8_t *data, size_t data_size,
                          const uint8_t expected_hash[SHA256_DIGEST_LENGTH],
                          uint8_t *comp_digest) {
    switch (alg) {
        case ALG_ZLIB: return test_zlib(data, data_size, expected_hash, comp_digest);
        case ALG_ZSTD: return test_zstd(data, data_size, expected_hash, comp_digest);
        case ALG_LZ4:  return test_lz4(data, data_size, expected_hash, comp_digest);
        case ALG_XZ:   return test_xz(data, data_size, expected_hash, comp_digest);
        case ALG_MEMCPY: return test_memcpy(data, data_size, expected_hash, comp_digest);
        default:       return -1; /* ALG_HAMMER is handled in the worker */
    }
}

/* Resolve the algorithm selection into an ordered list. Used by both the
 * workers and the vote coordinator so they always agree on the layout. */
static int resolve_algorithms(algorithm_t alg, algorithm_t out[NUM_ALGORITHMS]) {
    if (alg == ALG_ALL) {
        out[0] = ALG_ZSTD;
        out[1] = ALG_LZ4;
        out[2] = ALG_ZLIB;
        return NUM_ALGORITHMS;
    }
    out[0] = alg;
    return 1;
}

static void *worker_thread(void *arg) {
    worker_args_t *args = (worker_args_t *)arg;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(args->core_id, &cpuset);

    /* pthread functions return the error code directly, not via errno */
    int rc = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    if (rc != 0) {
        pthread_mutex_lock(args->print_mutex);
        fprintf(stderr, "[CORE %2d] ERROR: cannot set affinity: %s (core NOT tested)\n",
                args->core_id, strerror(rc));
        pthread_mutex_unlock(args->print_mutex);
        return NULL;
    }

    uint8_t *data = guarded_malloc(args->data_size);
    if (!data) {
        pthread_mutex_lock(args->print_mutex);
        fprintf(stderr, "[CORE %2d] ERROR: malloc failed (core NOT tested)\n", args->core_id);
        pthread_mutex_unlock(args->print_mutex);
        return NULL;
    }

    algorithm_t algorithms[NUM_ALGORITHMS];
    int alg_count = resolve_algorithms(args->algorithm, algorithms);

    /* Affinity and buffer are set up: the workload will actually run. */
    __sync_fetch_and_add(args->tested, 1);

    int core_errors = 0;
    /* In vote mode every core must see identical input per round. */
    uint64_t base_seed = args->vote ? VOTE_BASE_SEED
                                    : GOLDEN_RATIO_64 * (uint64_t)(args->core_id + 1);

    uint64_t hammer_golden = 0;
    int hammer_have_golden = 0;

    for (int iter = 0; !g_shutdown; iter++) {
        if (args->end_time) {
            if (time(NULL) >= args->end_time)
                break;
        } else if (iter >= args->iterations) {
            break;
        }

        const uint8_t *expected;
        uint8_t hash[SHA256_DIGEST_LENGTH];

        if (args->algorithm == ALG_HAMMER) {
            /* Hammer dwells on execution units; don't waste cycles filling
             * a data buffer it never reads. */
            expected = hash;
        } else if (args->kat) {
            /* Ground truth is the baked-in golden digest, computed on a
             * trusted machine - never anything produced by this core. */
            const kat_vector_t *v = &KAT_VECTORS[iter % KAT_VECTOR_COUNT];
            fill_layer_data(data, args->data_size, v->seed);
            expected = v->digest;
        } else {
            /* Fresh data every iteration: different patterns, different paths. */
            fill_layer_data(data, args->data_size, base_seed + (uint64_t)iter);
            SHA256(data, args->data_size, hash);
            expected = hash;
        }

        for (int a = 0; a < alg_count; a++) {
            uint8_t *slot = NULL;
            if (args->vote_digests)
                slot = args->vote_digests +
                       ((size_t)iter * alg_count + a) * SHA256_DIGEST_LENGTH;
            if (algorithms[a] == ALG_HAMMER) {
                uint64_t c = g_hammer(base_seed);
                if (slot)
                    SHA256((const uint8_t *)&c, sizeof(c), slot);
                if (!hammer_have_golden) {
                    /* Round-0 golden CAVEAT: a deterministically-wrong core
                     * adopts its own wrong answer as golden and passes.
                     * Cross-check with --vote (the herd is the reference)
                     * or a golden from a trusted machine. */
                    hammer_golden = c;
                    hammer_have_golden = 1;
                    pthread_mutex_lock(args->print_mutex);
                    printf("[CORE %2d] hammer golden=%016llx (%s)\n",
                           args->core_id, (unsigned long long)c, g_hammer_name);
                    pthread_mutex_unlock(args->print_mutex);
                    continue;
                }
                if (c != hammer_golden) {
                    core_errors++;
                    pthread_mutex_lock(args->print_mutex);
                    printf("[CORE %2d] CORRUPTION iter=%d algorithm=hammer "
                           "got=%016llx exp=%016llx\n",
                           args->core_id, iter,
                           (unsigned long long)c, (unsigned long long)hammer_golden);
                    pthread_mutex_unlock(args->print_mutex);
                }
                continue;
            }

            int rc = args->iopath
                ? test_iopath(algorithms[a], data, args->data_size, expected, slot,
                              args->core_id)
                : run_algorithm(algorithms[a], data, args->data_size, expected, slot);
            if (rc != 0) {
                core_errors++;
                pthread_mutex_lock(args->print_mutex);
                printf("[CORE %2d] CORRUPTION iter=%d algorithm=%s\n",
                       args->core_id, iter, alg_name(algorithms[a]));
                pthread_mutex_unlock(args->print_mutex);
            }
        }

        if (guard_check(data, args->data_size) != 0) {
            core_errors++;
            pthread_mutex_lock(args->print_mutex);
            printf("[CORE %2d] GUARD VIOLATION iter=%d (stray write near source buffer)\n",
                   args->core_id, iter);
            pthread_mutex_unlock(args->print_mutex);
        }

        if (args->verbose && (iter + 1) % VERBOSE_INTERVAL == 0) {
            pthread_mutex_lock(args->print_mutex);
            if (args->end_time)
                printf("[CORE %2d] %d iterations, %d errors\n",
                       args->core_id, iter + 1, core_errors);
            else
                printf("[CORE %2d] %d/%d iterations, %d errors\n",
                       args->core_id, iter + 1, args->iterations, core_errors);
            pthread_mutex_unlock(args->print_mutex);
        }

        /* Burst mode: let the core drop to idle so the next iteration
         * ramps clocks again. Marginal silicon often faults during
         * boost/power-state transitions, not under steady load. */
        if (args->burst_ms > 0 && !g_shutdown)
            usleep((useconds_t)args->burst_ms * 1000);
    }

    __sync_fetch_and_add(args->error_count, core_errors);

    guarded_free(data);
    return NULL;
}

/*
 * Read /sys topology for a logical CPU. Needed because vendor/RMA
 * diagnostics use per-socket physical core ids (which repeat across
 * sockets) while affinity uses logical CPU numbers - reconciling the two
 * by hand on a multi-socket Xeon is exactly where attribution gets lost.
 */
static int read_topology(int cpu, int *package, int *pcore) {
    char path[128];
    FILE *f;

    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu);
    f = fopen(path, "r");
    if (!f)
        return -1;
    if (fscanf(f, "%d", package) != 1) { fclose(f); return -1; }
    fclose(f);

    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/topology/core_id", cpu);
    f = fopen(path, "r");
    if (!f)
        return -1;
    if (fscanf(f, "%d", pcore) != 1) { fclose(f); return -1; }
    fclose(f);

    return 0;
}

static void print_topology_map(int offset, int num_cores) {
    printf("Logical CPU -> socket/physical-core mapping:\n");
    for (int i = 0; i < num_cores; i++) {
        int core = offset + i, pkg = -1, pc = -1;
        if (read_topology(core, &pkg, &pc) == 0)
            printf("  cpu %-4d socket %d, physical core %d\n", core, pkg, pc);
        else
            printf("  cpu %-4d (topology unavailable)\n", core);
    }
}

static void print_core_list(const char *label, const int *cores, int count) {
    printf("%s", label);
    for (int i = 0; i < count; i++) {
        int pkg = -1, pc = -1;
        printf("%d", cores[i]);
        if (read_topology(cores[i], &pkg, &pc) == 0)
            printf("(s%d/c%d)", pkg, pc);
        printf("%s", i < count - 1 ? ", " : "");
    }
    printf("\n");
}

/*
 * Returns EXIT_* bitmask: bit 0 set if any core showed corruption,
 * bit 1 set if any core could not be tested at all.
 */
static int run_sequential(int num_cores, int offset, const run_opts_t *opts) {
    printf("\n=== SEQUENTIAL: one core at a time ===\n");
    if (opts->duration_sec)
        printf("Cores: %d-%d | Duration: %ds | Block: %zu MB\n\n",
               offset, offset + num_cores - 1, opts->duration_sec,
               opts->data_size / (1024 * 1024));
    else
        printf("Cores: %d-%d | Iterations: %d | Block: %zu MB\n\n",
               offset, offset + num_cores - 1, opts->iterations,
               opts->data_size / (1024 * 1024));

    int total_errors = 0;
    int bad_cores[MAX_CORES];
    int bad_count = 0;
    int skipped_cores[MAX_CORES];
    int skip_count = 0;

    for (int i = 0; i < num_cores && !g_shutdown; i++) {
        int core = offset + i;
        printf("  core %2d ... ", core);
        fflush(stdout);

        int error_count = 0;
        int tested = 0;
        pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

        worker_args_t args = {
            .core_id = core,
            .iterations = opts->iterations,
            .data_size = opts->data_size,
            .algorithm = opts->algorithm,
            .error_count = &error_count,
            .tested = &tested,
            .print_mutex = &print_mutex,
            .verbose = opts->verbose,
            .kat = opts->kat,
            .iopath = opts->iopath,
            .burst_ms = opts->burst_ms,
            .end_time = opts->duration_sec ? time(NULL) + opts->duration_sec : 0,
        };

        pthread_t thread;
        int rc = pthread_create(&thread, NULL, worker_thread, &args);
        if (rc != 0) {
            printf("NOT TESTED (pthread_create: %s)\n", strerror(rc));
            skipped_cores[skip_count++] = core;
            continue;
        }
        pthread_join(thread, NULL);

        if (!tested) {
            /* Worker never ran the workload: this is NOT a pass. */
            printf("NOT TESTED\n");
            skipped_cores[skip_count++] = core;
        } else if (error_count > 0) {
            printf("FAIL (%d errors)\n", error_count);
            total_errors += error_count;
            bad_cores[bad_count++] = core;
        } else {
            printf("ok\n");
        }
    }

    printf("\n--- sequential results ---\n");
    if (bad_count > 0) {
        print_core_list("BAD CORES: ", bad_cores, bad_count);
        printf("(%d total errors)\n", total_errors);
    }
    if (skip_count > 0)
        print_core_list("UNTESTED CORES: ", skipped_cores, skip_count);
    if (bad_count == 0 && skip_count == 0)
        printf("ALL %d CORES CLEAN\n", num_cores);
    else if (bad_count == 0)
        printf("No corruption found, but %d core(s) were NOT tested - result is inconclusive\n",
               skip_count);

    return (bad_count > 0 ? EXIT_BAD_CORES : 0) | (skip_count > 0 ? EXIT_UNTESTED : 0);
}

/*
 * Returns EXIT_* bitmask, same as run_sequential.
 */
static int run_parallel(int num_cores, int offset, const run_opts_t *opts) {
    printf("\n=== PARALLEL: all cores at once ===\n");
    if (opts->duration_sec)
        printf("Cores: %d-%d | Duration: %ds | Block: %zu MB\n\n",
               offset, offset + num_cores - 1, opts->duration_sec,
               opts->data_size / (1024 * 1024));
    else
        printf("Cores: %d-%d | Iterations: %d | Block: %zu MB\n\n",
               offset, offset + num_cores - 1, opts->iterations,
               opts->data_size / (1024 * 1024));

    int errors[MAX_CORES] = {0};
    int tested[MAX_CORES] = {0};
    int created[MAX_CORES] = {0};
    pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

    pthread_t threads[MAX_CORES];
    worker_args_t args[MAX_CORES];

    for (int i = 0; i < num_cores; i++) {
        int core = offset + i;
        args[i] = (worker_args_t){
            .core_id = core,
            .iterations = opts->iterations,
            .data_size = opts->data_size,
            .algorithm = opts->algorithm,
            .error_count = &errors[i],
            .tested = &tested[i],
            .print_mutex = &print_mutex,
            .verbose = opts->verbose,
            .kat = opts->kat,
            .iopath = opts->iopath,
            .burst_ms = opts->burst_ms,
            .end_time = opts->duration_sec ? time(NULL) + opts->duration_sec : 0,
        };
        int rc = pthread_create(&threads[i], NULL, worker_thread, &args[i]);
        if (rc != 0) {
            pthread_mutex_lock(&print_mutex);
            fprintf(stderr, "[CORE %2d] ERROR: pthread_create: %s (core NOT tested)\n",
                    core, strerror(rc));
            pthread_mutex_unlock(&print_mutex);
        } else {
            created[i] = 1;
        }
    }

    for (int i = 0; i < num_cores; i++)
        if (created[i])
            pthread_join(threads[i], NULL);

    int total_errors = 0;
    int bad_cores[MAX_CORES];
    int bad_count = 0;
    int skipped_cores[MAX_CORES];
    int skip_count = 0;

    for (int i = 0; i < num_cores; i++) {
        int core = offset + i;
        if (!tested[i]) {
            skipped_cores[skip_count++] = core;
        } else if (errors[i] > 0) {
            total_errors += errors[i];
            bad_cores[bad_count++] = core;
        }
    }

    printf("\n--- parallel results ---\n");
    if (bad_count > 0) {
        print_core_list("BAD CORES: ", bad_cores, bad_count);
        printf("(%d total errors)\n", total_errors);
    }
    if (skip_count > 0)
        print_core_list("UNTESTED CORES: ", skipped_cores, skip_count);
    if (bad_count == 0 && skip_count == 0)
        printf("ALL %d CORES CLEAN\n", num_cores);
    else if (bad_count == 0)
        printf("No corruption found, but %d core(s) were NOT tested - result is inconclusive\n",
               skip_count);

    return (bad_count > 0 ? EXIT_BAD_CORES : 0) | (skip_count > 0 ? EXIT_UNTESTED : 0);
}

/*
 * Vote mode: all cores run identical input per round; the coordinator
 * groups cores by the SHA256 of their COMPRESSED output and majority
 * rules. Assumes bad cores are a minority and fail differently from each
 * other (use --kat for verdicts free of that assumption).
 */

typedef struct {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    int core;
} vote_entry_t;

static int vote_entry_cmp(const void *a, const void *b) {
    return memcmp(((const vote_entry_t *)a)->digest,
                  ((const vote_entry_t *)b)->digest, SHA256_DIGEST_LENGTH);
}

static void fprint_digest_hex(FILE *f, const uint8_t *d) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        fprintf(f, "%02x", d[i]);
}

static int run_vote(int num_cores, int offset, const run_opts_t *opts,
                     const char *digest_log) {
    printf("\n=== VOTE: all cores, identical input, majority rules ===\n");
    printf("Cores: %d-%d | Rounds: %d | Block: %zu MB\n\n",
           offset, offset + num_cores - 1, opts->iterations,
           opts->data_size / (1024 * 1024));

    algorithm_t algorithms[NUM_ALGORITHMS];
    int alg_count = resolve_algorithms(opts->algorithm, algorithms);
    size_t rounds = (size_t)opts->iterations * alg_count;

    int errors[MAX_CORES] = {0};
    int tested[MAX_CORES] = {0};
    int created[MAX_CORES] = {0};
    int dissent[MAX_CORES] = {0};
    pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_t threads[MAX_CORES];
    worker_args_t args[MAX_CORES];

    uint8_t *all_digests = calloc((size_t)num_cores * rounds, SHA256_DIGEST_LENGTH);
    if (!all_digests) {
        fprintf(stderr, "vote: out of memory\n");
        return EXIT_UNTESTED;
    }

    for (int i = 0; i < num_cores; i++) {
        int core = offset + i;
        args[i] = (worker_args_t){
            .core_id = core,
            .iterations = opts->iterations,
            .data_size = opts->data_size,
            .algorithm = opts->algorithm,
            .error_count = &errors[i],
            .tested = &tested[i],
            .print_mutex = &print_mutex,
            .verbose = opts->verbose,
            .kat = opts->kat,
            .iopath = opts->iopath,
            .burst_ms = opts->burst_ms,
            .end_time = opts->duration_sec ? time(NULL) + opts->duration_sec : 0,
            .vote = 1,
            .vote_digests = all_digests + (size_t)i * rounds * SHA256_DIGEST_LENGTH,
        };
        int rc = pthread_create(&threads[i], NULL, worker_thread, &args[i]);
        if (rc != 0) {
            pthread_mutex_lock(&print_mutex);
            fprintf(stderr, "[CORE %2d] ERROR: pthread_create: %s (core NOT tested)\n",
                    core, strerror(rc));
            pthread_mutex_unlock(&print_mutex);
        } else {
            created[i] = 1;
        }
    }

    for (int i = 0; i < num_cores; i++)
        if (created[i])
            pthread_join(threads[i], NULL);

    /* Digest log for offline verification on a trusted machine. */
    if (digest_log) {
        FILE *f = fopen(digest_log, "w");
        if (!f) {
            fprintf(stderr, "vote: cannot write %s: %s\n", digest_log, strerror(errno));
        } else {
            fprintf(f, "# vote digest log: core iter alg digest\n");
            for (int i = 0; i < num_cores; i++) {
                if (!tested[i])
                    continue;
                const uint8_t *d = all_digests + (size_t)i * rounds * SHA256_DIGEST_LENGTH;
                for (int iter = 0; iter < opts->iterations; iter++) {
                    for (int a = 0; a < alg_count; a++) {
                        fprintf(f, "core=%d iter=%d alg=%s digest=",
                                offset + i, iter, alg_name(algorithms[a]));
                        fprint_digest_hex(f, d + ((size_t)iter * alg_count + a) *
                                             SHA256_DIGEST_LENGTH);
                        fprintf(f, "\n");
                    }
                }
            }
            fclose(f);
            printf("Digest log: %s (re-verify offline on a trusted machine)\n", digest_log);
        }
    }

    /* Group cores by digest, round by round. */
    vote_entry_t entries[MAX_CORES];
    int compared_rounds = 0;
    int inconclusive_rounds = 0;

    for (size_t r = 0; r < rounds; r++) {
        int n = 0;
        for (int i = 0; i < num_cores; i++) {
            if (!tested[i])
                continue;
            memcpy(entries[n].digest,
                   all_digests + ((size_t)i * rounds + r) * SHA256_DIGEST_LENGTH,
                   SHA256_DIGEST_LENGTH);
            entries[n].core = offset + i;
            n++;
        }
        if (n < 2)
            continue; /* a vote needs at least two cores */
        compared_rounds++;
        qsort(entries, n, sizeof(vote_entry_t), vote_entry_cmp);

        /* Longest run of identical digests = the majority. */
        int best_start = 0, best_len = 0, i0 = 0;
        while (i0 < n) {
            int i1 = i0 + 1;
            while (i1 < n && memcmp(entries[i0].digest, entries[i1].digest,
                                    SHA256_DIGEST_LENGTH) == 0)
                i1++;
            if (i1 - i0 > best_len) {
                best_len = i1 - i0;
                best_start = i0;
            }
            i0 = i1;
        }
        if (best_len * 2 <= n) {
            /* No strict majority: cannot tell good from bad this round. */
            inconclusive_rounds++;
            continue;
        }
        for (int i = 0; i < n; i++)
            if (i < best_start || i >= best_start + best_len)
                dissent[entries[i].core - offset]++;
    }

    int bad_cores[MAX_CORES];
    int bad_count = 0;
    int skipped_cores[MAX_CORES];
    int skip_count = 0;
    for (int i = 0; i < num_cores; i++) {
        int core = offset + i;
        if (!tested[i])
            skipped_cores[skip_count++] = core;
        else if (errors[i] > 0 || dissent[i] > 0)
            bad_cores[bad_count++] = core;
    }

    printf("\n--- vote results (%d rounds compared) ---\n", compared_rounds);
    if (compared_rounds == 0) {
        printf("Nothing to compare: a vote needs at least 2 tested cores.\n");
        free(all_digests);
        return EXIT_UNTESTED;
    }
    if (bad_count > 0) {
        print_core_list("BAD CORES: ", bad_cores, bad_count);
        for (int i = 0; i < bad_count; i++) {
            int core = bad_cores[i];
            printf("  core %d: %d self-check error(s), dissented in %d round(s)\n",
                   core, errors[core - offset], dissent[core - offset]);
        }
    }
    if (skip_count > 0)
        print_core_list("UNTESTED CORES: ", skipped_cores, skip_count);
    if (inconclusive_rounds > 0)
        printf("WARNING: %d round(s) had no majority - inconclusive\n",
               inconclusive_rounds);
    if (bad_count == 0 && skip_count == 0 && inconclusive_rounds == 0)
        printf("ALL %d CORES AGREE IN EVERY ROUND (clean)\n", num_cores);

    free(all_digests);
    return (bad_count > 0 ? EXIT_BAD_CORES : 0) |
           ((skip_count > 0 || inconclusive_rounds > 0) ? EXIT_UNTESTED : 0);
}

static void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("\nCompression pipeline corruption tester.\n");
    printf("Compresses data, decompresses it, SHA256-verifies the output.\n");
    printf("Mirrors the Docker image pull decompression + digest check.\n\n");
    printf("Options:\n");
    printf("  -c, --cores N        Cores to test (default: all)\n");
    printf("  -o, --offset N       Start testing at core N (default: 0)\n");
    printf("  -i, --iterations N   Iterations per core (default: %d)\n", DEFAULT_ITERATIONS);
    printf("  -s, --size MB        Block size in MB (default: %d)\n", DEFAULT_BLOCK_MB);
    printf("  -a, --alg ALG        zlib | zstd | lz4 | xz | memcpy | hammer | all\n");
    printf("                       (default: all = zstd + lz4 + zlib)\n");
    printf("  -m, --mode MODE      sequential | parallel | both (default: both)\n");
    printf("  -V, --vote           Cross-core vote (parallel phase): identical input on\n");
    printf("                       all cores, majority rules on compressed digests\n");
    printf("      --digest-log F   Vote mode: write per-core digests to file F\n");
    printf("  -k, --kat            Known-answer test: verify against golden digests\n");
    printf("                       precomputed on a trusted machine (block: %d MB)\n",
           KAT_BLOCK_MB);
    printf("  -I, --iopath         Route blobs through the kernel (tmpfs write+read),\n");
    printf("                       mirroring docker's page-cache data path\n");
    printf("  -b, --burst MS       Sleep MS ms between iterations: idle<->boost\n");
    printf("                       transitions trigger marginal silicon (0 = off)\n");
    printf("  -T, --topology       Print logical CPU -> socket/physical-core map, exit\n");
    printf("  -d, --duration SEC   Run for SEC seconds instead of fixed iterations\n");
    printf("                       (not with --vote; rounds must be fixed)\n");
    printf("  -v, --verbose        Show progress\n");
    printf("  -h, --help           Help\n");
    printf("\nExit code: 0 = all tested cores clean, 1 = bad cores found,\n");
    printf("           2 = some cores untested, 3 = both\n");
}

static int get_num_cores(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return (n > 0) ? (int)n : 1;
}

int main(int argc, char **argv) {
    int num_cores = -1;
    int offset = 0;
    int iterations = DEFAULT_ITERATIONS;
    size_t data_size = (size_t)DEFAULT_BLOCK_MB * 1024 * 1024;
    algorithm_t algorithm = ALG_ALL;
    run_mode_t mode = MODE_BOTH;
    int verbose = 0;
    int kat = 0;
    int size_set = 0;
    int vote = 0;
    int iopath = 0;
    int burst_ms = 0;
    int topology = 0;
    int duration_sec = 0;
    const char *digest_log = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--cores") == 0) && i+1 < argc)
            num_cores = atoi(argv[++i]);
        else if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--offset") == 0) && i+1 < argc)
            offset = atoi(argv[++i]);
        else if ((strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--iterations") == 0) && i+1 < argc)
            iterations = atoi(argv[++i]);
        else if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--size") == 0) && i+1 < argc) {
            data_size = (size_t)atoi(argv[++i]) * 1024 * 1024;
            size_set = 1;
        }
        else if ((strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--alg") == 0) && i+1 < argc) {
            i++;
            if      (strcmp(argv[i], "zlib") == 0) algorithm = ALG_ZLIB;
            else if (strcmp(argv[i], "zstd") == 0) algorithm = ALG_ZSTD;
            else if (strcmp(argv[i], "lz4") == 0)  algorithm = ALG_LZ4;
            else if (strcmp(argv[i], "xz") == 0)   algorithm = ALG_XZ;
            else if (strcmp(argv[i], "memcpy") == 0) algorithm = ALG_MEMCPY;
            else if (strcmp(argv[i], "hammer") == 0) algorithm = ALG_HAMMER;
            else if (strcmp(argv[i], "all") == 0)  algorithm = ALG_ALL;
            else { fprintf(stderr, "Unknown alg: %s\n", argv[i]); return 1; }
        } else if ((strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--mode") == 0) && i+1 < argc) {
            i++;
            if      (strcmp(argv[i], "sequential") == 0) mode = MODE_SEQUENTIAL;
            else if (strcmp(argv[i], "parallel") == 0)   mode = MODE_PARALLEL;
            else if (strcmp(argv[i], "both") == 0)       mode = MODE_BOTH;
            else { fprintf(stderr, "Unknown mode: %s\n", argv[i]); return 1; }
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--kat") == 0) {
            kat = 1;
        } else if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--vote") == 0) {
            vote = 1;
        } else if (strcmp(argv[i], "--digest-log") == 0 && i+1 < argc) {
            digest_log = argv[++i];
        } else if (strcmp(argv[i], "-I") == 0 || strcmp(argv[i], "--iopath") == 0) {
            iopath = 1;
        } else if ((strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--burst") == 0) && i+1 < argc)
            burst_ms = atoi(argv[++i]);
        else if ((strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--duration") == 0) && i+1 < argc)
            duration_sec = atoi(argv[++i]);
        else if (strcmp(argv[i], "-T") == 0 || strcmp(argv[i], "--topology") == 0) {
            topology = 1;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (num_cores <= 0) num_cores = get_num_cores();
    if (offset < 0) offset = 0;
    if (iterations < 1) iterations = 1;
    if (offset + num_cores > MAX_CORES) num_cores = MAX_CORES - offset;

    if (kat) {
        if (size_set)
            printf("NOTE: --kat uses fixed %d MB vectors; ignoring --size\n", KAT_BLOCK_MB);
        data_size = KAT_BLOCK_BYTES;
    }
    if (burst_ms < 0)
        burst_ms = 0;
    if (duration_sec < 0)
        duration_sec = 0;
    if (duration_sec > 0 && vote) {
        fprintf(stderr, "--duration cannot be combined with --vote (rounds must be fixed)\n");
        return 1;
    }
    hammer_init();
    if (iopath) {
        g_iopath_dir = pick_iopath_dir();
        if (!g_iopath_dir) {
            fprintf(stderr, "--iopath: no writable tmpfs found (tried /dev/shm, /tmp)\n");
            return 1;
        }
    }
    if (topology) {
        print_topology_map(offset, num_cores);
        return 0;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Line-buffer stdout so status lines and stderr ERROR lines interleave
     * correctly when output is piped to a log file (e.g. overnight soak). */
    setvbuf(stdout, NULL, _IOLBF, 0);

    printf("Compression Pipeline Corruption Tester\n");
    printf("=======================================\n");
    printf("Cores:      %d", num_cores);
    if (offset > 0)
        printf(" (starting at core %d)", offset);
    printf("\n");
    printf("Iterations: %d\n", iterations);
    printf("Block:      %zu MB\n", data_size / (1024 * 1024));
    printf("Algorithm:  %s\n", algorithm == ALG_ALL ? "zstd + lz4 + zlib" : alg_name(algorithm));
    printf("Mode:       %s\n", mode == MODE_SEQUENTIAL ? "sequential" :
                                mode == MODE_PARALLEL ? "parallel" : "both");
    if (kat)
        printf("KAT:        %d golden vectors (digests from trusted machine)\n",
               KAT_VECTOR_COUNT);
    if (iopath)
        printf("IO path:    kernel round-trip via %s (docker blob path)\n", g_iopath_dir);
    if (burst_ms > 0)
        printf("Burst:      %d ms idle between iterations\n", burst_ms);
    if (duration_sec > 0)
        printf("Duration:   %d s (overrides iterations)\n", duration_sec);
    if (algorithm == ALG_HAMMER)
        printf("Hammer:     %s\n", g_hammer_name);

    run_opts_t opts = {
        .iterations = iterations,
        .data_size = data_size,
        .algorithm = algorithm,
        .verbose = verbose,
        .kat = kat,
        .iopath = iopath,
        .burst_ms = burst_ms,
        .duration_sec = duration_sec,
    };

    int result = EXIT_CLEAN;
    if (mode == MODE_SEQUENTIAL || mode == MODE_BOTH)
        result |= run_sequential(num_cores, offset, &opts);
    if (mode == MODE_PARALLEL || mode == MODE_BOTH) {
        if (vote)
            result |= run_vote(num_cores, offset, &opts, digest_log);
        else
            result |= run_parallel(num_cores, offset, &opts);
    }

    if (result & EXIT_UNTESTED)
        printf("\nWARNING: some cores were not tested (offline? container cpuset? "
               "insufficient memory?).\nA 'clean' result only covers the cores that "
               "actually ran the workload.\n");

    return result;
}
