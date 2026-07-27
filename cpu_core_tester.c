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
    volatile int *error_count;
    volatile int *completed;
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
 */
static void fill_layer_data(uint8_t *buf, size_t size) {
    size_t pos = 0;
    uint64_t seed = 0xDEADBEEFCAFEBABEULL;

    while (pos < size) {
        size_t chunk = (size - pos > 4096) ? 4096 : size - pos;

        uint8_t pattern = (uint8_t)((pos / 4096) % 5);
        switch (pattern) {
            case 0:
                memset(buf + pos, 0, chunk);
                break;
            case 1:
                memset(buf + pos, 0xAA, chunk);
                break;
            case 2:
                for (size_t i = 0; i < chunk; i++)
                    buf[pos + i] = (uint8_t)(i & 0xFF);
                break;
            case 3:
                for (size_t i = 0; i < chunk; i++) {
                    seed ^= seed >> 12;
                    seed ^= seed << 25;
                    seed ^= seed >> 27;
                    buf[pos + i] = (uint8_t)(seed & 0xFF);
                }
                break;
            case 4:
                for (size_t i = 0; i < chunk; i++)
                    buf[pos + i] = (uint8_t)('A' + (i % 26));
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
 * Compress -> decompress -> SHA256 verify.
 * Mirrors the Docker pull pipeline for a single layer chunk.
 * Returns 0 if the round-trip produces identical, hash-verified output.
 */
static int test_zlib(const uint8_t *data, size_t data_size,
                      const uint8_t expected_hash[32]) {
    Bytef *compressed = malloc(ZSTD_compressBound(data_size));
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
    c_stream.avail_out = ZSTD_compressBound(data_size);

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
        result = sha256_verify(decompressed, data_size, expected_hash);
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
        result = sha256_verify(decompressed, data_size, expected_hash);
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
        result = sha256_verify((uint8_t *)decompressed, data_size, expected_hash);
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

    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
        pthread_mutex_lock(args->print_mutex);
        fprintf(stderr, "[CORE %2d] ERROR: Failed to set affinity\n", args->core_id);
        pthread_mutex_unlock(args->print_mutex);
        return NULL;
    }

    uint8_t *data = malloc(args->data_size);
    if (!data) {
        pthread_mutex_lock(args->print_mutex);
        fprintf(stderr, "[CORE %2d] ERROR: malloc failed\n", args->core_id);
        pthread_mutex_unlock(args->print_mutex);
        return NULL;
    }

    fill_layer_data(data, args->data_size);

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(data, args->data_size, hash);

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

    int core_errors = 0;

    for (int iter = 0; iter < args->iterations && !g_shutdown; iter++) {
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
    __sync_fetch_and_add(args->completed, 1);

    free(data);
    return NULL;
}

static void run_sequential(int num_cores, int iterations, size_t data_size,
                            algorithm_t algorithm, int verbose) {
    printf("\n=== SEQUENTIAL: one core at a time ===\n");
    printf("Cores: %d | Iterations: %d | Block: %zu MB\n\n",
           num_cores, iterations, data_size / (1024 * 1024));

    int total_errors = 0;
    int bad_cores[MAX_CORES] = {0};
    int bad_count = 0;

    for (int core = 0; core < num_cores && !g_shutdown; core++) {
        printf("  core %2d ... ", core);
        fflush(stdout);

        int error_count = 0;
        int completed = 0;
        pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

        worker_args_t args = {
            .core_id = core,
            .iterations = iterations,
            .data_size = data_size,
            .algorithm = algorithm,
            .error_count = &error_count,
            .completed = &completed,
            .print_mutex = &print_mutex,
            .verbose = verbose,
        };

        pthread_t thread;
        if (pthread_create(&thread, NULL, worker_thread, &args) != 0) {
            printf("FAILED (thread)\n");
            continue;
        }
        pthread_join(thread, NULL);

        if (error_count > 0) {
            printf("FAIL (%d errors)\n", error_count);
            total_errors += error_count;
            bad_cores[bad_count++] = core;
        } else {
            printf("ok\n");
        }
    }

    printf("\n--- sequential results ---\n");
    if (bad_count > 0) {
        printf("BAD CORES: ");
        for (int i = 0; i < bad_count; i++)
            printf("%d%s", bad_cores[i], i < bad_count - 1 ? ", " : "");
        printf(" (%d total errors)\n", total_errors);
    } else {
        printf("ALL %d CORES CLEAN\n", num_cores);
    }
}

static void run_parallel(int num_cores, int iterations, size_t data_size,
                          algorithm_t algorithm, int verbose) {
    printf("\n=== PARALLEL: all cores at once ===\n");
    printf("Cores: %d | Iterations: %d | Block: %zu MB\n\n",
           num_cores, iterations, data_size / (1024 * 1024));

    int error_count = 0;
    int completed = 0;
    pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

    pthread_t threads[MAX_CORES];
    worker_args_t args[MAX_CORES];

    for (int core = 0; core < num_cores; core++) {
        args[core] = (worker_args_t){
            .core_id = core,
            .iterations = iterations,
            .data_size = data_size,
            .algorithm = algorithm,
            .error_count = &error_count,
            .completed = &completed,
            .print_mutex = &print_mutex,
            .verbose = verbose,
        };
        pthread_create(&threads[core], NULL, worker_thread, &args[core]);
    }

    for (int core = 0; core < num_cores; core++)
        pthread_join(threads[core], NULL);

    printf("\n--- parallel results ---\n");
    if (error_count > 0)
        printf("FAILED: %d total errors\n", error_count);
    else
        printf("ALL %d CORES CLEAN\n", num_cores);
}

static void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("\nCompression pipeline corruption tester.\n");
    printf("Compresses data, decompresses it, SHA256-verifies the output.\n");
    printf("Mirrors the Docker image pull decompression + digest check.\n\n");
    printf("Options:\n");
    printf("  -c, --cores N        Cores to test (default: all)\n");
    printf("  -i, --iterations N   Iterations per core (default: %d)\n", DEFAULT_ITERATIONS);
    printf("  -s, --size MB        Block size in MB (default: 16)\n");
    printf("  -a, --alg ALG        zlib | zstd | lz4 | all (default: all)\n");
    printf("  -m, --mode MODE      sequential | parallel | both (default: both)\n");
    printf("  -v, --verbose        Show progress\n");
    printf("  -h, --help           Help\n");
}

static int get_num_cores(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return (n > 0) ? (int)n : 1;
}

int main(int argc, char **argv) {
    int num_cores = -1;
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
    if (num_cores > MAX_CORES) num_cores = MAX_CORES;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("Compression Pipeline Corruption Tester\n");
    printf("=======================================\n");
    printf("Cores:      %d\n", num_cores);
    printf("Iterations: %d\n", iterations);
    printf("Block:      %zu MB\n", data_size / (1024 * 1024));
    printf("Algorithm:  %s\n", algorithm == ALG_ALL ? "zstd + lz4 + zlib" : alg_name(algorithm));
    printf("Mode:       %s\n", mode == MODE_SEQUENTIAL ? "sequential" :
                                mode == MODE_PARALLEL ? "parallel" : "both");

    if (mode == MODE_SEQUENTIAL || mode == MODE_BOTH)
        run_sequential(num_cores, iterations, data_size, algorithm, verbose);
    if (mode == MODE_PARALLEL || mode == MODE_BOTH)
        run_parallel(num_cores, iterations, data_size, algorithm, verbose);

    return 0;
}
