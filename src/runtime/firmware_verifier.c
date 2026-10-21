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

// Test/diff harness only: on a device the anchor and last_epoch come from
// unwritable storage and a monotonic counter, never from the command line.
int main(int argc, char *argv[]) {
    if (argc != 8) {
        fprintf(stderr, "Usage: %s <cert_path> <key_id_hex> <max_wcet_ns> <max_budget> <max_agents> <max_leakage> <last_epoch>\n", argv[0]);
        return 2;
    }

    const char *cert_path = argv[1];
    const char *key_id_hex = argv[2];

    hp_anchor_t anchor;
    anchor.max_wcet_ns = strtoull(argv[3], NULL, 10);
    anchor.max_budget = strtoull(argv[4], NULL, 10);
    anchor.max_agents = (uint8_t)atoi(argv[5]);
    anchor.max_leakage = (uint8_t)atoi(argv[6]);
    uint64_t last_epoch = strtoull(argv[7], NULL, 10);

    if (hex_to_bytes(key_id_hex, anchor.key_id, 32) != 0) {
        fprintf(stderr, "Invalid key_id hex\n");
        return 2;
    }

    FILE *f = fopen(cert_path, "rb");
    if (!f) {
        perror("fopen");
        return 2;
    }

    uint8_t cert[HP_CERT_SIZE];
    if (fread(cert, 1, HP_CERT_SIZE, f) != HP_CERT_SIZE) {
        fprintf(stderr, "Failed to read 512-byte certificate\n");
        fclose(f);
        return 2;
    }
    fclose(f);

    int res = verify_cert(cert, &anchor, last_epoch);

    if (res == 1) {
        printf("VERIFIED\n");
        return 0;
    } else {
        printf("REJECTED\n");
        return 1;
    }
}
