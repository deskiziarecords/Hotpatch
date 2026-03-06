#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "verify_cert.h"

static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    if (strlen(hex) != len * 2) return -1;
    for (size_t i = 0; i < len; i++) {
        if (sscanf(hex + i * 2, "%02hhx", &bytes[i]) != 1) return -1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 7) {
        fprintf(stderr, "Usage: %s <cert_path> <pubhash_hex> <max_wcet_ns> <max_budget> <max_agents> <max_epsilon>\n", argv[0]);
        return 2;
    }

    const char *cert_path = argv[1];
    const char *pubhash_hex = argv[2];
    uint64_t max_wcet_ns = strtoull(argv[3], NULL, 10);
    uint64_t max_budget = strtoull(argv[4], NULL, 10);
    uint8_t max_agents = (uint8_t)atoi(argv[5]);
    uint8_t max_epsilon = (uint8_t)atoi(argv[6]);

    uint8_t expected_pubhash[32];
    if (hex_to_bytes(pubhash_hex, expected_pubhash, 32) != 0) {
        fprintf(stderr, "Invalid pubhash hex\n");
        return 2;
    }

    FILE *f = fopen(cert_path, "rb");
    if (!f) {
        perror("fopen");
        return 2;
    }

    uint8_t cert[512];
    if (fread(cert, 1, 512, f) != 512) {
        fprintf(stderr, "Failed to read 512-byte certificate\n");
        fclose(f);
        return 2;
    }
    fclose(f);

    int res = verify_cert(cert, expected_pubhash, max_wcet_ns, max_budget, max_agents, max_epsilon);

    if (res == 1) {
        printf("VERIFIED\n");
        return 0;
    } else {
        printf("REJECTED\n");
        return 1;
    }
}
