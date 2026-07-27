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

#include <zlib.h>
#include <zstd.h>
#include <lz4.h>

#include <openssl/sha.h>

#define DEFAULT_ITERATIONS 100
#define MAX_CORES 1024

/* Exit codes: bit 0 = bad cores found, bit 1 = some cores untested */
#define EXIT_CLEAN     0
#define EXIT_BAD_CORES 1
#define EXIT_UNTESTED  2

typedef enum {
    ALG_ZLIB,
    ALG_ZSTD,
    ALG_LZ4,
    ALG_ALL,
} algorithm_t;

typedef enum {
    MODE_SEQUENTIAL,
    MODE_PARALLEL,
    MODE_BOTH,
} run_mode_t;

typedef struct {
    int core_id;
    int iterations;
    size_t data_size;
    algorithm_t algorithm;
    int *error_count;        /* per-core slot, written only by this worker */
    int *tested;             /* per-core slot: set to 1 only if the workload ran */
    pthread_mutex_t *print_mutex;
    int verbose;
} worker_args_t;

static volatile int g_shutdown = 0;

static void signal_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
}

/*
 * Generate varied data patterns that exercise different parts of the CPU.
 * Docker layers contain a mix of: zeros, repeated bytes, random data,
 * text-like sequences, and compressed-already data.
 *
 * The seed makes every iteration use a different buffer: marginal cores
 * usually fail only on specific data patterns, so identical input every
 * iteration drastically reduces the chance of catching them.
 */
static void fill_layer_data(uint8_t *buf, size_t size, uint64_t seed) {
    size_t pos = 0;
    uint64_t rng = seed ? seed : 0xDEADBEEFCAFEBABEULL;

    while (pos < size) {
        size_t chunk = (size - pos > 4096) ? 4096 : size - pos;

        uint8_t pattern = (uint8_t)(((pos / 4096) + seed) % 5);
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
                    rng ^= rng >> 12;
                    rng ^= rng << 25;
                    rng ^= rng >> 27;
                    buf[pos + i] = (uint8_t)(rng & 0xFF);
                }
                break;
            case 4:
                for (size_t i = 0; i < chunk; i++)
                    buf[pos + i] = (uint8_t)('A' + ((i + seed) % 26));
                break;
        }
        pos += chunk;
    }
}

/*
 * SHA256 a buffer. Returns 0 on match, -1 on mismatch.
 * This mirrors Docker's layer digest verification.
 */
static int sha256_verify(const uint8_t *data, size_t len, const uint8_t expected[32]) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);
    return memcmp(hash, expected, 32) == 0 ? 0 : -1;
}

/*
 * Verify the round-trip output. memcmp is the deterministic check; SHA256
 * mirrors the Docker digest verification on top of it.
 */
static int verify_output(const uint8_t *original, const uint8_t *decompressed,
                          size_t data_size, const uint8_t expected_hash[32]) {
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
                      const uint8_t expected_hash[32]) {
    uLong comp_bound = compressBound(data_size);
    Bytef *compressed = malloc(comp_bound);
    Bytef *decompressed = malloc(data_size);
    if (!compressed || !decompressed) {
        free(compressed); free(decompressed);
        return -1;
    }

    z_stream c_stream = {0};
    if (deflateInit(&c_stream, Z_DEFAULT_COMPRESSION) != Z_OK) {
        free(compressed); free(decompressed);
        return -1;
    }
    c_stream.next_in = (Bytef *)data;
    c_stream.avail_in = data_size;
    c_stream.next_out = compressed;
    c_stream.avail_out = comp_bound;

    if (deflate(&c_stream, Z_FINISH) != Z_STREAM_END) {
        deflateEnd(&c_stream);
        free(compressed); free(decompressed);
        return -1;
    }
    uLong comp_size = c_stream.total_out;
    deflateEnd(&c_stream);

    z_stream d_stream = {0};
    if (inflateInit(&d_stream) != Z_OK) {
        free(compressed); free(decompressed);
        return -1;
    }
    d_stream.next_in = compressed;
    d_stream.avail_in = comp_size;
    d_stream.next_out = decompressed;
    d_stream.avail_out = data_size;

    if (inflate(&d_stream, Z_FINISH) != Z_STREAM_END) {
        inflateEnd(&d_stream);
        free(compressed); free(decompressed);
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

    free(compressed);
    free(decompressed);
    return result;
}

static int test_zstd(const uint8_t *data, size_t data_size,
                      const uint8_t expected_hash[32]) {
    size_t comp_bound = ZSTD_compressBound(data_size);
    uint8_t *compressed = malloc(comp_bound);
    uint8_t *decompressed = malloc(data_size);
    if (!compressed || !decompressed) {
        free(compressed); free(decompressed);
        return -1;
    }

    size_t comp_size = ZSTD_compress(compressed, comp_bound, data, data_size, 3);
    if (ZSTD_isError(comp_size)) {
        free(compressed); free(decompressed);
        return -1;
    }

    size_t decomp_size = ZSTD_decompress(decompressed, data_size, compressed, comp_size);
    if (ZSTD_isError(decomp_size)) {
        free(compressed); free(decompressed);
        return -1;
    }

    int result = 0;
    if (decomp_size != data_size) {
        result = -1;
    } else {
        result = verify_output(data, decompressed, data_size, expected_hash);
    }

    free(compressed);
    free(decompressed);
    return result;
}

static int test_lz4(const uint8_t *data, size_t data_size,
                     const uint8_t expected_hash[32]) {
    int comp_bound = LZ4_compressBound(data_size);
    char *compressed = malloc(comp_bound);
    char *decompressed = malloc(data_size);
    if (!compressed || !decompressed) {
        free(compressed); free(decompressed);
        return -1;
    }

    int comp_size = LZ4_compress_default((const char *)data, compressed,
                                           data_size, comp_bound);
    if (comp_size <= 0) {
        free(compressed); free(decompressed);
        return -1;
    }

    int decomp_size = LZ4_decompress_safe(compressed, decompressed,
                                            comp_size, data_size);

    int result = 0;
    if (decomp_size != (int)data_size) {
        result = -1;
    } else {
        result = verify_output(data, (uint8_t *)decompressed, data_size, expected_hash);
    }

    free(compressed);
    free(decompressed);
    return result;
}

static const char *alg_name(algorithm_t alg) {
    switch (alg) {
        case ALG_ZLIB: return "zlib";
        case ALG_ZSTD: return "zstd";
        case ALG_LZ4:  return "lz4";
        default:       return "unknown";
    }
}

static int run_algorithm(algorithm_t alg, const uint8_t *data, size_t data_size,
                          const uint8_t expected_hash[32]) {
    switch (alg) {
        case ALG_ZLIB: return test_zlib(data, data_size, expected_hash);
        case ALG_ZSTD: return test_zstd(data, data_size, expected_hash);
        case ALG_LZ4:  return test_lz4(data, data_size, expected_hash);
        default:       return -1;
    }
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

    uint8_t *data = malloc(args->data_size);
    if (!data) {
        pthread_mutex_lock(args->print_mutex);
        fprintf(stderr, "[CORE %2d] ERROR: malloc failed (core NOT tested)\n", args->core_id);
        pthread_mutex_unlock(args->print_mutex);
        return NULL;
    }

    algorithm_t algorithms[3];
    int alg_count = 0;

    if (args->algorithm == ALG_ALL) {
        algorithms[0] = ALG_ZSTD;
        algorithms[1] = ALG_LZ4;
        algorithms[2] = ALG_ZLIB;
        alg_count = 3;
    } else {
        algorithms[0] = args->algorithm;
        alg_count = 1;
    }

    /* Affinity and buffer are set up: the workload will actually run. */
    __sync_fetch_and_add(args->tested, 1);

    int core_errors = 0;
    uint64_t base_seed = 0x9E3779B97F4A7C15ULL * (uint64_t)(args->core_id + 1);

    for (int iter = 0; iter < args->iterations && !g_shutdown; iter++) {
        /* Fresh data every iteration: different patterns, different paths. */
        fill_layer_data(data, args->data_size, base_seed + (uint64_t)iter);

        uint8_t hash[SHA256_DIGEST_LENGTH];
        SHA256(data, args->data_size, hash);

        for (int a = 0; a < alg_count; a++) {
            if (run_algorithm(algorithms[a], data, args->data_size, hash) != 0) {
                core_errors++;
                pthread_mutex_lock(args->print_mutex);
                printf("[CORE %2d] CORRUPTION iter=%d algorithm=%s\n",
                       args->core_id, iter, alg_name(algorithms[a]));
                pthread_mutex_unlock(args->print_mutex);
            }
        }

        if (args->verbose && (iter + 1) % 10 == 0) {
            pthread_mutex_lock(args->print_mutex);
            printf("[CORE %2d] %d/%d iterations, %d errors\n",
                   args->core_id, iter + 1, args->iterations, core_errors);
            pthread_mutex_unlock(args->print_mutex);
        }
    }

    __sync_fetch_and_add(args->error_count, core_errors);

    free(data);
    return NULL;
}

static void print_core_list(const char *label, const int *cores, int count) {
    printf("%s", label);
    for (int i = 0; i < count; i++)
        printf("%d%s", cores[i], i < count - 1 ? ", " : "");
    printf("\n");
}

/*
 * Returns EXIT_* bitmask: bit 0 set if any core showed corruption,
 * bit 1 set if any core could not be tested at all.
 */
static int run_sequential(int num_cores, int offset, int iterations, size_t data_size,
                            algorithm_t algorithm, int verbose) {
    printf("\n=== SEQUENTIAL: one core at a time ===\n");
    printf("Cores: %d-%d | Iterations: %d | Block: %zu MB\n\n",
           offset, offset + num_cores - 1, iterations, data_size / (1024 * 1024));

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
            .iterations = iterations,
            .data_size = data_size,
            .algorithm = algorithm,
            .error_count = &error_count,
            .tested = &tested,
            .print_mutex = &print_mutex,
            .verbose = verbose,
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
static int run_parallel(int num_cores, int offset, int iterations, size_t data_size,
                          algorithm_t algorithm, int verbose) {
    printf("\n=== PARALLEL: all cores at once ===\n");
    printf("Cores: %d-%d | Iterations: %d | Block: %zu MB\n\n",
           offset, offset + num_cores - 1, iterations, data_size / (1024 * 1024));

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
            .iterations = iterations,
            .data_size = data_size,
            .algorithm = algorithm,
            .error_count = &errors[i],
            .tested = &tested[i],
            .print_mutex = &print_mutex,
            .verbose = verbose,
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

static void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("\nCompression pipeline corruption tester.\n");
    printf("Compresses data, decompresses it, SHA256-verifies the output.\n");
    printf("Mirrors the Docker image pull decompression + digest check.\n\n");
    printf("Options:\n");
    printf("  -c, --cores N        Cores to test (default: all)\n");
    printf("  -o, --offset N       Start testing at core N (default: 0)\n");
    printf("  -i, --iterations N   Iterations per core (default: %d)\n", DEFAULT_ITERATIONS);
    printf("  -s, --size MB        Block size in MB (default: 16)\n");
    printf("  -a, --alg ALG        zlib | zstd | lz4 | all (default: all)\n");
    printf("  -m, --mode MODE      sequential | parallel | both (default: both)\n");
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
    size_t data_size = 16 * 1024 * 1024;
    algorithm_t algorithm = ALG_ALL;
    run_mode_t mode = MODE_BOTH;
    int verbose = 0;

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
        else if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--size") == 0) && i+1 < argc)
            data_size = (size_t)atoi(argv[++i]) * 1024 * 1024;
        else if ((strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--alg") == 0) && i+1 < argc) {
            i++;
            if      (strcmp(argv[i], "zlib") == 0) algorithm = ALG_ZLIB;
            else if (strcmp(argv[i], "zstd") == 0) algorithm = ALG_ZSTD;
            else if (strcmp(argv[i], "lz4") == 0)  algorithm = ALG_LZ4;
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

    int result = EXIT_CLEAN;
    if (mode == MODE_SEQUENTIAL || mode == MODE_BOTH)
        result |= run_sequential(num_cores, offset, iterations, data_size, algorithm, verbose);
    if (mode == MODE_PARALLEL || mode == MODE_BOTH)
        result |= run_parallel(num_cores, offset, iterations, data_size, algorithm, verbose);

    if (result & EXIT_UNTESTED)
        printf("\nWARNING: some cores were not tested (offline? container cpuset? "
               "insufficient memory?).\nA 'clean' result only covers the cores that "
               "actually ran the workload.\n");

    return result;
}
