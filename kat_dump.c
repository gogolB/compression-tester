/*
 * kat_dump - regenerate the golden KAT digests baked into cpu_core_tester.c.
 *
 * ONLY build and run this on a TRUSTED (known-good) machine. It prints a
 * ready-to-paste KAT_VECTORS table to stdout. Required whenever
 * fill_layer_data() or KAT_BLOCK_BYTES changes.
 *
 * Build: make kat-dump
 */
#define main tester_main
#include "cpu_core_tester.c"
#undef main

int main(void) {
    uint8_t *data = malloc(KAT_BLOCK_BYTES);
    if (!data) {
        perror("malloc");
        return 1;
    }

    printf("static const kat_vector_t KAT_VECTORS[KAT_VECTOR_COUNT] = {\n");
    for (int v = 0; v < KAT_VECTOR_COUNT; v++) {
        uint8_t digest[SHA256_DIGEST_LENGTH];
        fill_layer_data(data, KAT_BLOCK_BYTES, KAT_VECTORS[v].seed);
        SHA256(data, KAT_BLOCK_BYTES, digest);

        printf("    { 0x%016llXULL, {", (unsigned long long)KAT_VECTORS[v].seed);
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            printf("%s0x%02X,", (i % 8 == 0) ? "\n        " : " ", digest[i]);
        printf("\n    } },\n");
    }
    printf("};\n");

    free(data);
    return 0;
}
